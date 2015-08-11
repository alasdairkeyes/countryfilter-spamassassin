# Copyright 2015 Alasdair Keyes
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

=head1 NAME

Mail::SpamAssassin::Plugin::CountryFilter - CountryFilter plugin

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::CountryFilter

=head1 REVISION

  Revision: 0.02 

=head1 DESCRIPTION

  Mail::SpamAssassin::Plugin::CountryFilter is a plugin to allow users to
  score messages based on the country of origin or the country of the relays
  it passes through.

  To find out more see
  https://github.com/alasdairkeyes/countryfilter-spamassassin

=head1 AUTHOR

  Alasdair Keyes <alasdair@akeyes.co.uk>

  https://akeyes.co.uk/

=head1 LICENSE

  http://www.apache.org/licenses/LICENSE-2.0

=cut

package Mail::SpamAssassin::Plugin::CountryFilter;
 
use strict;
use warnings;
 
use Mail::SpamAssassin;
use Mail::SpamAssassin::Constants qw(:ip);
our @ISA = qw(Mail::SpamAssassin::Plugin);
 
use Geo::IP;
use Net::IP;

my $config_key = "country_filter";

## Constructor 

    sub new {
        my ($class, $mailsa) = @_;
        $class = ref($class) || $class;
        my $self = $class->SUPER::new( $mailsa );
        bless ($self, $class);

        # Register functions with Spamassassin
        $self->register_eval_rule ( 'blacklist_relay_country_check' );
        $self->register_eval_rule ( 'whitelist_relay_country_check' );

        $self->register_eval_rule ( 'blacklist_source_country_check' );
        $self->register_eval_rule ( 'whitelist_source_country_check' );
 
        return $self;
    }



    sub _clean_and_split_codes {
        my $string = shift || "";

        # Uppercase it all
        $string = uc($string);
        
        # Remove anything other than A-Z and commas (,)
        $string =~ s/[^,A-Z]//g;

        # Remove duplicates so there are no empty string elements
        $string =~ s/,+/,/g;

        # return hashref where keys are the unique country codes
        return { map { $_ => 1 } split(/,/, $string) };
    }




    sub _get_all_public_ips {
        my $pms = shift || {};
        
        # Get all the IPs
        my @fullips = map { $_->{ip} } @{$pms->{relays_untrusted}};

        my @fullexternal = map {
            (!$_->{internal}) ? ($_->{ip}) : ()
            } @{$pms->{relays_trusted}};
        push (@fullexternal, @fullips);   # add untrusted set too

        # Strip out private IPs
        my $IP_PRIVATE = IP_PRIVATE;
        @fullexternal = grep {
            $_ !~ /$IP_PRIVATE/
        } @fullexternal;

        dbg("Pulled following IPs from PMS relays " . join(', ', @fullexternal));

        return @fullexternal;
    }



    sub _get_relay_public_ips {
        my $pms = shift || {};
        my @relay_ips = _get_all_public_ips($pms);
        
        # Shift off the source
        pop(@relay_ips);

        # Return the rest
        return @relay_ips;
    }



    sub _get_source_public_ip {
        my $pms = shift || {};
        my @relay_ips = _get_all_public_ips($pms);

        # Get the source and return it
        my $source_public_ip = pop(@relay_ips);
        return $source_public_ip;
    }


    # Override standard debug method by prepending it with $config_key for easier
    # checking in the logs
    sub dbg {
        my @message = @_;
        Mail::SpamAssassin::Plugin::dbg($config_key .': ' . (join(' ',@_) || '-'));
    }



    sub _ip_to_country_code {
        my $self    = shift;
        my $ip      = shift;

        # Load Net::IP object, and check version
        my $net_ip = Net::IP->new($ip)
            || do {
                dbg("Failed to load Net::IP for ip '$ip'");
                return;
            };

        my $ip_version = $net_ip->version;
        if (! grep { $ip_version eq $_ } qw/ 4 6 /) {
            dbg("Invalid IP version '$ip_version' to load Geo::IP");
            return;
        }


        # Get the Database file for this IP version
        my $db_file = $self->{ main }{ conf }{ $config_key }{ join('', 'geoip_ipv', $ip_version, '_database') }
            || '';

        # Load up suitable Geo::IP object
        my $geo_ip;
        if ($db_file) {
            $geo_ip = eval {
                Geo::IP->open($db_file, GEOIP_STANDARD);
            } || do {
                dbg("Failed to instantiate Geo::IP v$ip_version with '$db_file': " , $@);
                return;
            };
        } else {
            if ($ip_version == 4) {
                $geo_ip = eval {
                    Geo::IP->new(GEOIP_STANDARD)
                } || dbg("Failed to instantiate Geo::IP v$ip_version: " , $@);
            } else {
                dbg("Failed to instantiate Geo::IP v$ip_version: No Database file");
                return;
            }
        }

        # Get right function to call
        my $function = "country_code_by_addr";
        $function .= '_v6'
            if ($ip_version == 6);
      
 
        # Get country code
        if (my $country = $geo_ip->$function($ip)) {
            dbg("IP $ip maps to country code $country");
            return $country;
        } else {
            dbg("Failed to map " . ($ip || '-') . " to country code - No Data in GeoIP");
        }

        return;
    }



    sub _check_ip_country_codes {
        my $self            = shift;
        my $country_codes   = shift;
        my @ips             = @_;

        my @matches;
        foreach my $ip (@ips) {

            # When lint mode is run or SA is started up, this will be undefined, catch it
            next unless defined($ip);

            if (my $country = $self->_ip_to_country_code($ip)) {
                push(@matches,"$ip|$country")
                    if ($country_codes->{ $country });
            }
        }

        return @matches;
    }



    sub parse_config {
        my ($self, $opts) = @_;

        foreach my $option_key (qw/ blacklist_relay_country_codes whitelist_relay_country_codes blacklist_source_country_codes whitelist_source_country_codes geoip_ipv4_database geoip_ipv6_database /) {
            if ($opts->{key} eq $option_key) {

                dbg("Loading " . ($opts->{ user_config } ? "user" : "global" ) . "_config for $option_key");

                my $values_string = $opts->{ value };

                my $value;
                if ($option_key =~ /_country_codes$/) {
                    $value = _clean_and_split_codes($values_string);
                    dbg("$option_key loaded as " . join(',',keys(%$value)));
                } else {
                    $value = $values_string;
                    dbg("$option_key loaded as " . $value);
                }

                # Store
                $self->{ main }{ conf }{ $config_key }{ $option_key } = $value;

                # Inform SA, we handle this option
                $self->inhibit_further_callbacks();
                return 1;
            }
        }

        return 0;
    }




    sub blacklist_source_country_check {
        my ($self, $pms) = @_;
            
        my $country_codes = $self->{ main }{ conf }{ $config_key }{ blacklist_source_country_codes };

        my $source_public_ip = _get_source_public_ip($pms);
        dbg("Checking Source IP " . ($source_public_ip || '-') . " against blacklist countries " . join(',',keys(%$country_codes)));

        my @matches = $self->_check_ip_country_codes($country_codes, $source_public_ip);
        
        return 1
            if (scalar(@matches)); 

        return 0;
    }



    sub whitelist_source_country_check {
        my ($self, $pms) = @_;

        my $country_codes = $self->{ main }{ conf }{ $config_key }{ whitelist_source_country_codes };

        my $source_public_ip = _get_source_public_ip($pms);
        dbg("Checking Source IP " . ($source_public_ip || '-') . " against whitelist countries " . join(',',keys(%$country_codes)));

        my @matches = $self->_check_ip_country_codes($country_codes, $source_public_ip);
        
        return 1
            if (scalar(@matches)); 

        return 0;
    }



    sub blacklist_relay_country_check {
        my ($self, $pms) = @_;

        my $country_codes = $self->{ main }{ conf }{ $config_key }{ blacklist_relay_country_codes };

        my @relay_ips = _get_relay_public_ips($pms);
       
        dbg("Checking Relay IPs " . join(', ', @relay_ips) . " against blacklist countries " . join(',',keys(%$country_codes)));
       
        my @matches = $self->_check_ip_country_codes($country_codes, @relay_ips);
        
        return 1
            if (scalar(@matches)); 

        return 0;
    }



    sub whitelist_relay_country_check {
        my ($self, $pms) = @_;

        my $country_codes = $self->{ main }{ conf }{ $config_key }{ whitelist_relay_country_codes };

        my @relay_ips = _get_relay_public_ips($pms);
       
        dbg("Checking Relay IPs " . join(', ', @relay_ips) . " against whitelist countries " . join(',',keys(%$country_codes)));
       
        my @matches = $self->_check_ip_country_codes($country_codes, @relay_ips);
        
        return 1
            if (scalar(@matches)); 

        return 0;
    }

1;

=head1 METHODS

=over

=item B<new( $class, $sa )>

  Plugin constructor

  Registers the rules with SpamAssassin

=item B<parse_config( $self, $opts )>

  SpamAssassin default config parsing method.

  Loads the blacklist/whitelist data from the global/user
  configuration files

=item B<blacklist_source_country_check( $self, $pms )>

  Registered method

  Called by SpamAssassin to check source country against blacklist

=item B<whitelist_source_country_check( $self, $pms )>

  Registered method

  Called by SpamAssassin to check source country against whitelist

=item B<blacklist_relay_country_check( $self, $pms )>

  Registered method

  Called by SpamAssassin to check relay countries against blacklist

=item B<whitelist_relay_country_check( $self, $pms )>

  Registered method

  Called by SpamAssassin to check relay countries against whitelist

=item B<dbg(@message)>

  Redefine SpamAssassin's dbg function, prepends with country_filter text,
  Makes debugging easier

=item B<_clean_and_split_codes( $config_value )>

  Takes config line of comma seperated values of ISO 3166-1 alpha-2
  codes and turns them into hashref
  
  Data is cleaned of whitespace and other incorrect characters and
  converted to uppercase

  {
    XX => 1,
    XY => 1,
  }

=item B<_get_all_public_ips( $pms )>

  Takes the Spamassassin Per-message-status object and pulls
  out all non-private Relay IPs that this message has touched
  Returns an array of IP addresses

=item B<_get_relay_public_ips( $pms )>

  Takes the Spamassassin Per-message-status and returns relay IPs
  (all IPs except the non-private IP the message originates from)

  Returns an array of IP addresses

=item B<_get_souce_public_ip( $pms )>

  Takes the Spamassassin Per-message-status and returns the source IP
  (first non-private IP)

  Returns IP address as scalar

=item B<_ip_to_country_code( $ip )>

  Checks IP version, creates Geo::IP object with the database for
  that version and gets the Country Code

=item B<_check_ip_country_codes( \%country_codes, @ip_addresses )>

  Takes countrycode hash and array of IPs as arguments

  Iterates through given IPs, determines the country and pushes any matches
  with the country codes into an array.

  Returns an array of matched IP addresses
  Array elements are of format '1.2.3.4|$country'

=back


=cut

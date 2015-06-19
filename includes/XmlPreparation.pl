#!/usr/bin/perl
use strict;
use File::Compare;
use File::Spec;
use File::Copy;

# Get the names
my @InFiles = @ARGV;

my $Overs = '';
my $OutString = '';
my $CurrFile = '';
my $ThisFile;
my $depth=0;

foreach $ThisFile (@InFiles) {
    my @AllLines = ();
    open (IN, "$ThisFile") or die "Can't open $ThisFile for reading\n";
    while(<IN>) { push(@AllLines, $_) }
    close(IN);

    my @values = split(/(, |\{|\[|\}|\])/, @AllLines[0]);
    my @new = ();
    my $tab=1;
    my $indent='  ';

    foreach my $val (@values) {
        if (length $val) {
            $val =~ s/\s+$//;
            if ($val eq "{") {
                if ($tab) {
                    push(@new, $indent x $depth);
                }
                else {
                    push (@new, ' ');
                }
                $tab = 1;
                push (@new, $val);
                push(@new, "\n");
                $depth++;
            }
            elsif ($val eq "}") { 
                $depth--;
                push(@new, "\n");
                push(@new, $indent x $depth);
                push (@new, $val);
            }
            elsif ($val eq "[") {
                if ($tab) {
                    push(@new, $indent x $depth);
                }
                else {
                    push (@new, ' ');
                }
                $tab = 1;
                push (@new, $val);
                push(@new, "\n");
                $depth++;
            }
            elsif ($val eq "]") { 
                push(@new, "\n");
                $depth--;
                push(@new, $indent x $depth);
                push (@new, $val);
            }
            elsif ($val eq ",") {
                push (@new, $val);
                push (@new, "\n");
                $tab = 1;
            }
            else {
                push(@new, $indent x $depth);
                push (@new, $val);
                $tab = 0;
            }                
        }
    }

    my @parts;
    @values = ();
    foreach my $val (split(/\n/, join('', @new))) {
        if (length $val > 65) {
            @parts = $val =~ /(.{1,65})/g;
            push (@values, @parts);
        }
        else {
            push (@values, $val);
        }
    }

    print ("<figure><artwork type='CBORdiag'><![CDATA[\n");
    print (join("\n", @values));
    print ("]]></artwork></figure>\n");

    exit 0;
    
        # Check for lines greater than 71
#        if(length($AllLines[$lineno]) > 71) {
#            my $LineNoToPrint = $lineno+1;
#            $Overs .= "$ThisFile: $LineNoToPrint\n";
#        }

        #
        #  Other changes for the purposes of draft checking
        #


#        $OutString .= $AllLines[$lineno];


    # Copy it with the right top and bottom to ForDraft with a different name
#	open(INCL, ">$ThisFile.incl") or
#        die "Could not write to $ThisFile.incl\n";
#	print INCL '<figure><artwork><![CDATA[', "\n",
#        join ('', @AllLines), ']]></artwork></figure>', "\n";
#	close(INCL);
}

if ($CurrFile){ print "Did not close file '$CurrFile'\n"; }

if($Overs) { print "Over-long lines:\n" . $Overs; }
else { print "No over-long lines.\n" }


sub StartNewFile {
    my $TheNewFile = shift(@_);
    chomp($TheNewFile);
    $TheNewFile =~ s/ //g;
    print "Start new file '$TheNewFile'\n";
    if ($CurrFile ne '') { die "Can't currently do nested files - new file $CurrFile \n" }
    
    open (OUT2, ">ForDraft/$TheNewFile") or 
        die "Could not open ForDraft/$TheNewFile\n"; 
    
    $CurrFile = $TheNewFile;
    $OutString = '';
}

sub EndCurrFile {
    my $FileToEnd = shift(@_);
    chomp($FileToEnd);
    $FileToEnd =~ s/ //g;
    print "Close file '$FileToEnd'\n";
    if ($CurrFile ne $FileToEnd) { die "Mismached file names $CurrFile and $FileToEnd\n" }
    print OUT2 '<figure><artwork><![CDATA[', "\n",
    $OutString, ']]></artwork></figure>', "\n";
    close(OUT2);
    $CurrFile = '';
}

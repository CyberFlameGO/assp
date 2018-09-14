    -d "$base/mrtg" or mkdir "$base/mrtg",0755;
    open my $file, ">$base/mrtg/assp-mrtg.cfg";
    binmode $file;
    print $file <<EOT;
# Created by for current statistic
# assp public@$localhostip


### Global Config Options

#  for UNIX
# WorkDir: /home/http/mrtg

#  or for NT
# WorkDir: c:\mrtgdata

### Global Defaults

#  to get bits instead of bytes and graphs growing to the right
# Options[_]: growright, bits

EnableIPv6: no
NoMib2: Yes
LoadMIBs: C:/usr/share/snmp/mibs/ASSP-MIB.txt
interval: 5
RunAsDaemon:yes


######################################################################
# System: $localhostname
# IP : $localhostip
# assp_myName: $myName
######################################################################

EOT
    my $j = scalar @sortedOIDs;

    for (my $i = 0;$i < $j;$i++) {
        if ($sortedOIDs[$i] =~ /^\.4\.([15])\.\d+\.0$/o) {
            my $ws = $1;
            my $tl = ($ws == 1) ? 'current' : 'currentScored';
            my $nameid = $sortedOIDs[$i];
            $nameid =~ s/0$/1/o;
            my $name = $tl.&SNMPderefVal($subOID{$nameid});
            next if $name =~ /^current(?:mailCount|avgdamped|cpuAvg|cpuBusyTime|cpuTime|damptime|msgPerDay|nextUpload|smtpConcurrentSessions|smtpMaxConcurrentSessions|starttime|statstart|uptime|version|memoryUsage)$/io;
            $nameid =~ s/1$/2/o;
            my $desc;
            $desc = &SNMPderefVal($subOID{$nameid}) if exists $subOID{$nameid};
            $desc =~ s/\s*:\s*$//o;
            $desc =~ s/^\s+//o;
            $desc =~ s/\s+$//o;
            my $countType = 'mails';
            $desc =~ /connect/io and $countType = 'connections';
            $ws == 5 and $desc = 'currently scored '.$desc;
            
            print $file <<EOT;
#########################
# $desc
#########################
Target[$myName.$name]: $name.0&$name.0:public\@$localhostip: * 12
MaxBytes[$myName.$name]: 25000000000
Title[$myName.$name]: ASSP $desc Analysis for $myName -- $localhostname
YLegend[$myName.$name]: $desc
ShortLegend[$myName.$name]: $countType
Legend1[$myName.$name]: $countType count
Legend2[$myName.$name]:
Legend3[$myName.$name]: Max $desc
Legend4[$myName.$name]:
LegendI[$myName.$name]: &nbsp;$countType per day:
LegendO[$myName.$name]:
WithPeak[$myName.$name]: ywmd
Options[$myName.$name]: growright, nopercent, perhour

PageTop[$myName.$name]: <h1>ASSP $desc Analysis for $myName -- $localhostname</h1>
		<div id="sysdetails">
			<table>
				<tr>
					<td>System:</td>
					<td>$localhostname</td>
				</tr>
				<tr>
					<td>Description:</td>
					<td>$desc  </td>
				</tr>
				<tr>
					<td>Ip:</td>
					<td>$localhostip ($localhostname)</td>
				</tr>
			</table>
		</div>

EOT
        }
    }
    close $file;


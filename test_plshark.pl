use plshark;
my $object = new plshark("sample.pcap");
my $proto = $object->proto("frame", 0);
my @nodes = $proto->findnodes(".//*[\@name=\"frame.time\"]");
for my $node (@nodes)
{
	print $node->toString();
	print "\n";
	print $node->{"showname"};
}
#$node()
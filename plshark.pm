package plshark;
use XML::LibXML;

my $_tshark_path="C:\\Program Files\\Wireshark\\tshark.exe";
sub new
{
	my $class = shift;
	my $self = {
		_file => shift,
		_args => shift,
	};
	#print "File is $self->{_file}\n";
	$result = `"$_tshark_path" -T pdml -r $self->{_file} $self->{_args}`;
	#print $result;
	my $dom = XML::LibXML->new->load_xml(string => $result);
	$self->{_dom} = $dom;
	bless $self, $class;
	return $self;
}
sub proto{
	my ( $self, $proto , $packet) = @_;
	if ($packet > 0) {
		$packet = $packet + 1;
	}
	else {
		$packet = 1
	}
	print $packet
	my @nodes = $self->{_dom}->findnodes("/pdml/packet[$packet]/proto[\@name=\"$proto\"]");
	return @nodes[0];
}
sub tshark_path{
	my $class = shift;
	$_tshark_path = shift;
}
sub get_tshark_path{
	return $_tshark_path;
}
1;
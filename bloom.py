# ./pox.py bloom --localnet=10.0.0.0/8 forwarding.l2_learning py
# POX> core.bloom.add(('IPV4 172.18.0.4', 'ICMP'))
# POX> core.bloom.rm(('IPV4 172.18.0.4', 'ICMP'))

# Juergen Fitschen (me@jfitschen.de)  and Zhen Cao (zhencao.ietf@gmail.com)


from pox.core import core
from pox.lib.revent import EventHalt
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
import hashlib

log = core.getLogger()

class BloomFilter( object ):
	def __init__( self, length, hashfunc ):
		# Save hash function
		self.hashfunc = hashfunc

		# Setup array for storing Bloom filter
		self.bloom = []
		i = 0
		while i < length:
			self.bloom.append( False )
			i = i + 1

	def calc( self, val ):
		# Get index based on tuple val
		h = self.hashfunc()

		for t in val:
			h.update( str(t) )

		return int( h.hexdigest(), 16 ) % len( self.bloom )

	def add( self, flow ):
		# Adds a new flow to the filter
		i = self.calc( flow )
		self.bloom[i] = True

	def rm( self, flow ):
		# Remove a flow from the filter
		i = self.calc( flow )
		self.bloom[i] = False

	def __eq__(self, other):
		# Lookup whether given flow is stored in the filter
		if self.bloom[ self.calc( other ) ]:
			return True
		else:
			return False

	def __ne__(self, other):
		return not self.__eq__( other )



class MultiBloomFilter( object ):
	def __init__( self, length, hashfunc ):
		# Create a set of Bloom filter
		self.bloom = []
		for h in hashfunc:
			self.bloom.append( BloomFilter( length, h ) )

	def add( self, flow ):
		# Add a new flow to all filters
		for b in self.bloom:
			b.add( flow )

	def rm( self, flow ):
		# Remove a flow from all filters
		for b in self.bloom:
			b.rm( flow )

	def __eq__( self, other ):
		# Check whether given flow is installed in all filters
		ok = True
		for b in self.bloom:
			ok = ok and (b == other)

		return ok
			
	def __ne__(self, other):
		# Check whether given flow is not installed in any filter
		return not self.__eq( other )



class bloom( object ):
	def __init__( self, localnet):
		# Store the local net
		self.localnet = localnet
		self.length = 128

		# Initiate a new Bloom filter set
		self.bloom = MultiBloomFilter( self.length, (hashlib.md5,) )
		log.info( "Initiated Bloom Filter" )
		# manually adding some entries 
		'''i = 0
		prefix = 'IPV4 10.0.'
		prtl = 'ICMP'
		numofhosts = 200

		while i <= (numofhosts/256):
			# 10.0.0.1 when i = 0, but 10.0.1.0 when i = 1
			if i==0:
				j = 1
			else: 
				j = 0
			while j <= min(255, numofhosts - i*256):
				self.bloom.add((prefix+str(i)+'.'+str(j), prtl))
				j = j + 1
			i = i + 1
		'''
		#log.info("-bloom filter initialized-")

		# Register this filter with high priority. Packets entering switches are checked.
		# If packets are blocked, the PacketIn event is halted; other modules won't receive it.
		core.openflow.addListenerByName( "PacketIn", self._handle_packetIn, priority=1 )

	def add( self, flow ):
		self.bloom.add( flow )

	def rm( self, flow ):
		self.bloom.rm( flow )

	def _handle_packetIn( self, event ):
		dpid = event.connection.dpid
		inport = event.port

		# Fingerprint for the flow
		fp = []

		### LAYER 2
		packet = event.parsed
		if not packet or not isinstance( packet, pkt.ethernet ):
			# Bypass unparsed packets and non-Ethernet frames
			return

		### LAYER 3
		packet = packet.next
		if isinstance(packet, pkt.arp):
			# Bypass ARP request
			return
		elif isinstance(packet, pkt.ipv4):
#			if packet.dstip == "255.255.255.255" or IPAddr(packet.dstip).inNetwork(self.localnet):
				# Bypass broadcast packets and packets to local network
			if packet.dstip == "255.255.255.255" :
				# Bypass broadcast packet only
				return
			else:
				fp.append( "IPV4 " + str(packet.dstip) )
		else:
			return EventHalt

		### LAYER 4
		packet = packet.payload
		if isinstance( packet, pkt.udp ):
			fp.append( "UDP " + str(packet.dstport) )
		elif isinstance( packet, pkt.tcp ):
			fp.append( "TCP " + str(packet.dstport) )
		elif isinstance( packet, pkt.icmp ):
			fp.append( "ICMP" )
		else:
			# Drop other packets
			return EventHalt


		### CHECK FINGERPRINT AGAINST BLOOM FILTER
		if not tuple( fp ) == self.bloom:
			# Not in Bloom filter
			log.info( "Dropped " + str(fp) )
			return EventHalt
		else:
			# Allowed destination
			return


def launch( localnet = "0.0.0.0/32"):
	core.registerNew( bloom, localnet )

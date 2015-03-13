# ./pox.py nobloom --localnet=10.0.0.0/8 forwarding.l2_learning py
# POX> core.nobloom.add(('IPV4 172.18.0.4', 'ICMP'))
# POX> core.nobloom.rm(('IPV4 172.18.0.4', 'ICMP'))


from pox.core import core
from pox.lib.revent import EventHalt
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
import hashlib

log = core.getLogger()

class NoBloomFilter( object ):
	def __init__( self):

		# Setup array for storing a plain filter
		self.filter = {}


	def add( self, flow ):
		# Adds a new flow to the filter

		# search the filter, if there is not an existing entry, then add one
		
		if not flow in self.filter:
			self.filter[flow] = True


	def rm( self, flow ):
		# Remove a flow from the filter
		#i = self.calc( flow )
		#self.bloom[i] = False
		
		if flow in self.filter:
			del self.filter[flow]
	
	def selfprint(self):
		i = 0; 
		for flow in self.filter:
			i += 1
		print i


	def __eq__(self, other):
		# Lookup whether given flow is stored in the filter
		ret = False
		for flow in self.filter:
			if flow == other:
				ret = True
		return ret

	def __ne__(self, other):
		return not self.__eq__( other )


class nobloom( object ):
	def __init__( self, localnet ):
		# Store the local net
		self.localnet = localnet

		# Initiate a new Bloom filter set
		self.nobloom = NoBloomFilter()
		log.info( "Initiated non-Bloom Filter" )

                # manually adding all the addresses, examples below
                '''i = 0
                prefix = 'IPV4 10.0.'
                prtl = 'ICMP'
                numofhosts = 200 # hosts number < 65535

                while i <= (numofhosts/256):
                        # 10.0.0.1 when i = 0, but 10.0.1.0 when i = 1
                        if i==0:
                                j = 1
                        else:
                                j = 0
                        while j <= min(255, numofhosts - i*256):
                                self.nobloom.add((prefix+str(i)+'.'+str(j), prtl))
                                j = j + 1
                        i = i + 1
		self.nobloom.selfprint()
		'''

		# Register this filter with high priority. Packets entering switches are checked.
		# If packets are blocked, the PacketIn event is halted; other modules won't receive it.
		core.openflow.addListenerByName( "PacketIn", self._handle_packetIn, priority=1 )

	def add( self, flow ):
		self.nobloom.add( flow )

	def rm( self, flow ):
		self.nobloom.rm( flow )

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

		### CHECK FINGERPRINT AGAINST noBLOOM FILTER
		if not tuple( fp ) == self.nobloom:
			# Not in NoBloom filter
			log.info( "Dropped " + str(fp) )
			return EventHalt
		else:
			# Allowed destination
			return


def launch( localnet = "0.0.0.0/32"):
	core.registerNew( nobloom, localnet )


from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

class MyTopo(Topo):
    def build(self):
        h1 = self.addHost('h1', ip='10.0.0.1')
        h2 = self.addHost('h2', ip='10.0.0.2')

        s1 = self.addSwitch('s1', protocols='OpenFlow13')

        self.addLink(h1, s1)
        self.addLink(h2, s1)

def run():
    topo = MyTopo()
    net = Mininet(topo=topo,
                  switch=OVSSwitch,
                  controller=None)
    
    net.addController('c0', controller=RemoteController,
                      ip='127.0.0.1', port=6633)
    
    net.start()
    print("*** Network started")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
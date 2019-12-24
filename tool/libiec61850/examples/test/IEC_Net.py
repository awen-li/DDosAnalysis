#!/usr/bin/python

#mn --custom /home/mininet/IEC_Net.py --topo IEC
from mininet.topo import Topo

class IEC_Net(Topo):
    def __init__(self):

        Topo.__init__(self)

        Host1  = self.addHost('ied1')
        Host2  = self.addHost('ied2')
        Router = self.addHost('router')
        Attack = self.addHost('attack')
        Switch = self.addSwitch('s1')

        self.addLink(Host1, Switch)
        self.addLink(Host2, Switch)
        self.addLink(Router, Switch)
        self.addLink(Attack, Router)

topos = {'IEC': (lambda: IEC_Net()) }
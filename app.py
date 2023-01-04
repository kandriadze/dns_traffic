from flask import Flask, render_template
from scapy.layers.dns import DNS
from scapy.all import *


# function to store the DNS traffic data
class CircularBuffer:
    def __init__(self, size):
        self.size = size
        self.buffer = [None] * size
        self.index = 0

    def add(self, data):
        self.buffer[self.index] = data
        self.index = (self.index + 1) % self.size

    def get(self):
        return self.buffer[self.index:] + self.buffer[:self.index]


#  function to capture and analyze the DNS traffic
def capture_dns_traffic():
    circular_buffer = CircularBuffer(100)

    def dns_callback(packet):
        if packet.haslayer(DNS):
            #  the timestamp, domain name, and DNS response
            timestamp = packet.time
            domain_name = packet[DNS].qd.qname
            dns_response = packet[DNS].an.rdata

            # Add the information to the circular buffer
            circular_buffer.add((timestamp, domain_name, dns_response))

    #  Scapy's sniff function to capture packets on the network and filter for DNS packets
    sniff(prn=dns_callback, filter="udp and port 53", store=0)

    # Return the current contents of the circular buffer
    return circular_buffer.get()


#  new Flask app
app = Flask(__name__)

@app.route('/')
def home():

    dns_traffic = capture_dns_traffic()

    return render_template('template.html', dns_traffic=dns_traffic)


# Run the Flask app
if __name__ == '__main__':
    app.run()
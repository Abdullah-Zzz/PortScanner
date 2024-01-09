from scapy.all import *
import concurrent.futures
import socket

#making packets, sending them and checking the response and if the response has tcp layer 
# and has the flas 0x12 which is SYN response (0x14 SYN-ACK ).

try:

    def port_scanning(target, port):
        packet=IP(dst=target) / TCP(dport=int(port), flags="S")

        response=sr1(packet, timeout=1, verbose=0)

        if response and response.haslayer(TCP) and response[TCP].flags == 0x12: 
            service = socket.getservbyport(int(port))
            return f"port {port} ({service}) is open. "

        elif response and response.haslayer(TCP) and response[TCP].flags == 0x14:
            return f"port {port} is close."
        else:
            return f"port {port} is close."

    def parallel_scanning():
        #taing inputs
        target=input("Target: ")
        port_input=input("port (comma-separated or range) : ")

        #Splitting the input For example: 80,443 output: ['80','443']
        ports=port_input.split(",")

        #storing open ports
        open_ports=[]

        #to scan ranges
        if "-" in port_input:
            ports=range(int(port_input.split("-")[0]), int(port_input.split("-")[1])+1)

        #parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            port_scans={ executor.submit(port_scanning, target, port): port for port in ports} 
            for future in concurrent.futures.as_completed(port_scans):
                result=future.result()
            
                open_ports.append(result)
        #filtring out closed ports when scanning for ranges
        if "-" in port_input:
            open_ports = [port for port in open_ports if "close" not in port]

                    
        print("Open ports:", open_ports)

    parallel_scanning() 

except Scapy_Exception as se :
    print(f"Error: {se}")
except PermissionError as p :
    print(f"Error: {p}")
except OSError as o :
    print(f"Error: {o}")
except Exception as e :
    print(f"Error: {e}")


                

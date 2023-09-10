# Adit_Rutwik_Networks_Assignment
This is assignment1 for the Computer Networks course

Adit Kaushik - 21110010
Rutwik More - 21110133


Question 1---
  
  sniffer.py has a while True loop. To run this, first execute "sudo python3 sniffer.py" on your terminal. Then, on a separate terminal, run the command
  "sudo tcpreplay -i enp0s1 --mbps 50 -v ~/assignment1/q1/0_.pcap". The sniffer will start sniffing the packets and will display the 4 tuple for TCP.

  Follow the same steps as sniffer.py for running reverse_lookup.py. The program will terminate as soon as it finds 5 IP addresses which can be reversed-looked up.


Question 2---

  Runn the file checksum.py using the command "sudo python3 checksum.py". Then, in a separate terminal, run the command "sudo tcpreplay -i enp0s1 --mbps 50 -v ~/assignment1/q2/3_.pcap".

  Follow the same step as checksum.py for other 4 .py files.


Question 3---

  Run the file port_number_to_process_id.py using the command "sudo python3 port_number_to_process_id.py". Then in a separate terminal, run the command
  "sudo tcpreplay -i enp0s1 --mbps 50 -v ~/assignment1/q2/3_.pcap".

  Now wait for 30 seconds for the program to run. Once it has collected all the packets, it will display a list of available ports and prompt you to enter a port. Enter a port number
  from the listed ports. The program will then display the process id associated with it if it exists.

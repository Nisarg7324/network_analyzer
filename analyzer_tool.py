'''
#######################
# AUTHOR: Nisarg Dave #
# Network Analyzer    #
# Capstone Project    #
#######################
'''

from tkinter import Tk, ttk # For GUI programming
import subprocess # For executing commands (cmd line) and get their output in python
import requests # For crafting and sending API requests
import json # For parsing json data as API response will be in json format

class Color:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ORANGE = '\033[38;5;208m'
    END = '\033[0m'

# Global variable to store old information
global temp
temp = {}

# netstat -ano | findstr "ESTABLISHED"
# The above command allows us to see all establshed connections made by any application/process from the system to an IP address
# It also gives us the destination IP address and the PID (a.k.a Process ID) of the process that is responsible for that connection
# The output format of the command would be as follows:
# Protocol_Name Local_IP_Address:Local_Port Destination_IP_Address:Destination_Port ESTABLISHED PID 

# Function to get output of the command: netstat -ano | findstr "ESTABLISHED"
def get_netstat_connections_info():
    try:
        #netstat_ano_output = subprocess.check_output(['netstat', 'ano'])
        #findstr_output = subprocess.check_output(['findstr', 'ESTABLISHED'], input = netstat_ano_output)
        netstat_command = "netstat -ano | findstr ESTABLISHED"
        netstat_output = subprocess.Popen(netstat_command, shell = True, stdout = subprocess.PIPE, stderr = subprocess.DEVNULL)
        output, _ = netstat_output.communicate() 
        established_connections = output.decode("utf-8").splitlines()
        return established_connections # This will be a list of strings in the format of command output shown above (line #8)
    except subprocess.CalledProcessError:
        return []

# Function to extract PID from the netstat output so that it can be used later to find process name
# This function will also map destination IP address with the PID that is responsible for establishing this connection
def get_ip_pid(connections):
    ipaddr_pid_map = {} # The format of this dictionary will be {Destination IP address : PID}
    for connection in connections:
        output_parts = connection.split()
        # As seen in line #8, there are 5 parts of the output separated by whitespace. Hence, 3rd and 5th part are Destination IP address and PID respectively.
        # IP address can be in IPv4 or IPv6 format
        destination_ip_addr_port = output_parts[2] # This represents IPv4:Port and/or [IPv6]:Port . We need to handle these separately
        if "[" in destination_ip_addr_port:
            # This means it has IPv6 address in the format [IPv6]:Port
            destination_ip_addr = destination_ip_addr_port[destination_ip_addr_port.index("[") + 1:destination_ip_addr_port.index("]")]
        else:
            # This means it has IPv4 address in the format IPv4:Port
            destination_ip_addr = destination_ip_addr_port.split(":")[0]
        pid = output_parts[4]
        ipaddr_pid_map[destination_ip_addr] = pid
    return ipaddr_pid_map

# tasklist /FI "PID eq ENTER_PID_HERE" | findstr ".exe"
# The above command yields information of the executable that has the same PID as "ENTER_PID_HERE". That is, replace "ENTER_PID_HERE" with the PID you want to find info about
# The output format of the above command is as follows:
# <Image or Process Name> <PID> <Session Name> <Session Number> <Memory Usage> 

# Function to get process name from a given PID
def get_process_name(pid):
    pid_name_map = {} # The format of this dictionary will be {PID : Process Name}
    pid_name_command = f'tasklist /FI "PID eq {pid}" | findstr ".exe"'
    pid_name_command_output = subprocess.Popen(pid_name_command, shell = True, stdout = subprocess.PIPE, stderr = subprocess.DEVNULL)
    output, _ = pid_name_command_output.communicate()
    # As seen in line #45, the first part is the process name which we need
    process_name = output.decode("utf-8").split()[0]
    return process_name

# This function stores old info on ip-pid values for future use
def store_old_info(ip_pid_info):
    global temp
    temp = ip_pid_info

# This function returns the old info stored
def get_old_info():
    global temp
    return temp

# This function conducts the analysis using AbuseIPDB API
def analyze_ip(ip_addresses):
    analysis_report = {} # The format of this dictionary will be {IP Address : "safe"/"unsafe"/"potential"/"undetermined"}
    
    # Safe means that the AbuseIPDB's abuse confidence score is 0
    # Potential means that the AbuseIPDB's abuse confidence score is more than 0 but equal or less than 50
    # Unsafe means that the AbuseIPDB's abuse confidence score is more than 50
    # Undetermined means no data/abuse confidence score is available
    # Maximum abuse confidence score is 100
    
    # Crafting the API request URL
    api_req_url = 'https://api.abuseipdb.com/api/v2/check'
    
    # API request headers
    api_req_headers = {
        'Accept': 'application/json',
        'Key': '' # Insert API Key here. I removed it since this is a public repository.
    }
    
    # Sending API requests for each IP address and getting a response
    for ip in ip_addresses:
        if ip == '127.0.0.1':
            continue
        api_querystring = {
            'ipAddress': ip
        }
        
        print(f"checking for ip: {ip}") ###!!! DEBUG PURPOSE !!!###
        
        api_response = requests.request(method = 'GET', url = api_req_url, headers = api_req_headers, params = api_querystring)
        # Converting the API response into JSON format
        api_response_json = api_response.json()
        # Extract the AbuseIPDB's abuse confidence score
        abuseipdb_confidence_score = api_response_json['data']['abuseConfidenceScore']
        # Analyze the score as per criteria defined above
        if abuseipdb_confidence_score == 0:
            analysis_report[ip] = 'safe'
        elif abuseipdb_confidence_score > 0 and abuseipdb_confidence_score <= 50:
            analysis_report[ip] = 'potential'
        elif abuseipdb_confidence_score > 50:
            analysis_report[ip] = 'unsafe'
        else:
            analysis_report[ip] = 'undetermined'
    
    print(analysis_report) ###!!! DEBUG PURPOSE !!!###
    
    return analysis_report

# Function to display results in GUI
# This function displays results in the form of a Table with headings: PID, Process Name, Destination IP Address
# This function also refreshes the table contents every 1 minute
def create_and_update_table():
    netstat_output = get_netstat_connections_info()
    ip_pid_info = get_ip_pid(netstat_output)
    # First, we clear any previous entries. Will be useful when this function is recursively called
    for row in table.get_children():
        table.delete(row)
    
    # Now, we fill the table with information provided
    for ip, pid in ip_pid_info.items():
        proc_name = get_process_name(pid)
        if(ip == "127.0.0.1"):
            continue
        table.insert("", "end", values = (pid, proc_name, ip))
    
    # To avoid repeatedly analyzing same IP address in each iteration, we only check the new ones. This will limit the rate of API calls and optimize the algorithm
    ip_pid_info_old = get_old_info()
    new_ips = set(ip_pid_info.keys()) - set(ip_pid_info_old.keys())
    
    print(f"Now checking: {new_ips}") ###!!! DEBUG PURPOSE !!!###
    
    print("Conducting Analysis...") ###!!! DEBUG PURPOSE !!!###
    
    # Analyze the new IP addresses only
    analysis_result = analyze_ip(new_ips)
    
    print("Analysis done!") ###!!! DEBUG PURPOSE !!!###
    
    # Now we color-code the table rows based on the analysis report
    # Light Green -> Safe
    # Light Orange -> Potential
    # Light Red -> Unsafe
    # Light Yellow -> Undetermined
    if len(analysis_result) > 0:
        for item in table.get_children():
            table_values = table.item(item, 'values')
            ip_addr = table_values[2]
            #print(f"updating color of ip: {ip_addr}") ###!!! DEBUG PURPOSE !!!###
            try:
                if analysis_result[ip_addr] == 'safe':
                    table.tag_configure(item, background = '#ccffcc') # Light Green
                    table.update_idletasks()
                    print(Color.GREEN + "IP " + ip_addr + " is safe" + Color.END) ###!!! DEBUG PURPOSE !!!###
                elif analysis_result[ip_addr] == 'potential':
                    table.tag_configure(item, background = '#ffcc99') # Light Orange
                    table.update_idletasks()
                    print(Color.ORANGE + "IP " + ip_addr + " is potentially unsafe" + Color.END) ###!!! DEBUG PURPOSE !!!###
                elif analysis_result[ip_addr] == 'unsafe':
                    table.tag_configure(item, background = '#ffcccc') # Light Red
                    table.update_idletasks()
                    print(Color.RED + "IP " + ip_addr + " is unsafe" + Color.END) ###!!! DEBUG PURPOSE !!!###
                else:
                    table.tag_configure(item, background = '#ffffcc') # Light Yellow
                    table.update_idletasks()
                    print(Color.YELLOW + "IP " + ip_addr + " is not determined" + Color.END) ###!!! DEBUG PURPOSE !!!###
                
            except KeyError:
                continue
            
    
    # Before recalling this function, we will store the current dictionary containing ip-pid info so that we can compare with the new one in the next iteration
    store_old_info(ip_pid_info)
    
    # We call the this function recursively after 1 minute (or 60,000 milliseconds)
    root.after(60000, create_and_update_table)

# Main function
if __name__ == "__main__":
    # Defining GUI Window and Table
    root = Tk()
    root.title("Network Analyzer")
    table = ttk.Treeview(root, columns = ('PID', 'Process Name', 'Destination IP Address'), show = 'headings')
    table.heading('PID', text = 'PID')
    table.heading('Process Name', text = 'Process Name')
    table.heading('Destination IP Address', text = 'Destination IP Address')
    table.pack(fill = 'both', expand = True)
    
    # Calling function that will now fill the table with results and keep updating it every 1 minute
    create_and_update_table()
    

    root.mainloop()

import socket
import concurrent.futures

def check_port(ip, port, timeout=0.5):
    """
    Checks if a single TCP port is open.
    
    Args:
        ip (str): Target IP address.
        port (int): Port number.
        timeout (float): Socket timeout in seconds.
        
    Returns:
        bool: True if open, False if closed/filtered/error.
    """
    try:
        # AF_INET = IPv4, SOCK_STREAM = TCP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            # connect_ex returns 0 on success
            result = s.connect_ex((ip, port))
            if result == 0:
                return True
            return False
    except Exception as e:
        return False

def scan_ports(ip, ports, timeout=0.5, max_workers=50):
    """
    Scans a list of ports on a target IP.
    
    Args:
        ip (str): Target IP address.
        ports (list): List of port integers to scan.
        timeout (float): Socket timeout in seconds for each port check.
        max_workers (int): Number of threads to use for scanning.
        
    Returns:
        list: A list of open ports (int).
    """
    # Use a ThreadPoolExecutor to scan ports in parallel 
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Map each future to its port number
        future_to_port = {executor.submit(check_port, ip, port, timeout): port for port in ports}
        
        open_ports = []
        for future in concurrent.futures.as_completed(future_to_port):
            try:
                if future.result():
                    open_ports.append(future_to_port[future])
            except Exception:
                # Ignore per-port errors
                pass
                
    return sorted(open_ports)
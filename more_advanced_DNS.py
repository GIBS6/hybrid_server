# Section 1: Importing Libraries
import dns.resolver
import dns.message
import socket
import logging
import time
import collections
import random
import ipaddress
import ftplib
import os
import threading
from datetime import datetime, timedelta
import argparse
import json
import hashlib
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Advanced DNS Server')
    parser.add_argument('--child', action='store_true', help='Run in child mode')
    args = parser.parse_args()


# Section 2: Setting up Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Create a logger for the DNS server
logger = logging.getLogger('dns_server')

# Set up a file handler to log messages to a file
file_handler = logging.FileHandler('dns_server.log')
file_handler.setLevel(logging.INFO)

# Create a formatter and attach it to the file handler
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

# Add the file handler to the logger
logger.addHandler(file_handler)

# Section 3: Rate Limiter Class
class RateLimiter:
    def __init__(self, max_requests, time_window):
        """
        Initialize the rate limiter with a maximum number of requests and a time window.

        Args:
            max_requests (int): The maximum number of requests allowed within the time window.
            time_window (int): The time window in seconds.
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.request_timestamps = collections.defaultdict(list)

    def is_allowed(self, ip_address):
        """
        Check if a request from the given IP address is allowed.

        Args:
            ip_address (str): The IP address of the request.

        Returns:
            bool: True if the request is allowed, False otherwise.
        """
        try:
            current_time = time.time()
            timestamps = self.request_timestamps[ip_address]
            timestamps = [timestamp for timestamp in timestamps if current_time - timestamp < self.time_window]
            self.request_timestamps[ip_address] = timestamps
            if len(timestamps) < self.max_requests:
                timestamps.append(current_time)
                return True
            return False
        except Exception as e:
            logger.error(f"Error checking rate limit: {e}")
            return False

# Section 4: IP Blacklist Class
class IPBlacklist:
    def __init__(self, blacklist_file='blacklist.txt'):
        """
        Initialize the IP blacklist.

        Args:
            blacklist_file (str): The file path to the blacklist file.
        """
        self.blacklist_file = blacklist_file
        self.blacklisted_ips = self.load_blacklist()

    def load_blacklist(self):
        """
        Load the IP blacklist from the blacklist file.

        Returns:
            set: A set of blacklisted IP addresses.
        """
        try:
            with open(self.blacklist_file, 'r') as file:
                return set(line.strip() for line in file.readlines())
        except FileNotFoundError:
            return set()

    def save_blacklist(self):
        """
        Save the IP blacklist to the blacklist file.
        """
        try:
            with open(self.blacklist_file, 'w') as file:
                for ip in self.blacklisted_ips:
                    file.write(ip + '\n')
        except Exception as e:
            logger.error(f"Error saving blacklist: {e}")

    def add_ip(self, ip):
        """
        Add an IP address to the blacklist.

        Args:
            ip (str): The IP address to add.
        """
        try:
            self.blacklisted_ips.add(ipaddress.ip_address(ip))
            self.save_blacklist()
        except ValueError:
            logger.error(f"Invalid IP address: {ip}")

    def remove_ip(self, ip):
        """
        Remove an IP address from the blacklist.

        Args:
            ip (str): The IP address to remove.
        """
        try:
            self.blacklisted_ips.remove(ipaddress.ip_address(ip))
            self.save_blacklist()
        except ValueError:
            logger.error(f"Invalid IP address: {ip}")

    def is_blacklisted(self, ip):
        """
        Check if an IP address is blacklisted.

        Args:
            ip (str): The IP address to check.

        Returns:
            bool: True if the IP address is blacklisted, False otherwise.
        """
        try:
            return ipaddress.ip_address(ip) in self.blacklisted_ips
        except ValueError:
            logger.error(f"Invalid IP address: {ip}")
            return False
# Section 5: Cache Class
class Cache:
    def __init__(self, cache_size=1000):
        """
        Initialize the cache.

        Args:
            cache_size (int): The maximum size of the cache.
        """
        self.cache_size = cache_size
        self.cache = collections.OrderedDict()

    def get(self, query):
        """
        Get the cached result for a query.

        Args:
            query (str): The query to get the cached result for.

        Returns:
            The cached result, or None if not found.
        """
        try:
            if query in self.cache:
                result = self.cache.pop(query)
                self.cache[query] = result  # Move to end to mark as recently used
                return result
            return None
        except Exception as e:
            logger.error(f"Error getting cache: {e}")
            return None

    def set(self, query, result):
        """
        Set the cached result for a query.

        Args:
            query (str): The query to set the cached result for.
            result: The result to cache.
        """
        try:
            if query in self.cache:
                self.cache.pop(query)
            elif len(self.cache) >= self.cache_size:
                self.cache.popitem(last=False)  # Remove oldest item
            self.cache[query] = result
        except Exception as e:
            logger.error(f"Error setting cache: {e}")

# Section 6: Load Balancer Class
class LoadBalancer:
    def __init__(self, dns_servers):
        """
        Initialize the load balancer with a list of DNS servers.

        Args:
            dns_servers (list): A list of DNS server IP addresses.
        """
        self.dns_servers = dns_servers
        self.server_index = 0

    def get_dns_server(self):
        """
        Get the next DNS server in the list.

        Returns:
            str: The IP address of the next DNS server.
        """
        try:
            server = self.dns_servers[self.server_index]
            self.server_index = (self.server_index + 1) % len(self.dns_servers)
            return server
        except Exception as e:
            logger.error(f"Error getting DNS server: {e}")
            return None

    def add_dns_server(self, server):
        """
        Add a DNS server to the list.

        Args:
            server (str): The IP address of the DNS server.
        """
        try:
            self.dns_servers.append(server)
        except Exception as e:
            logger.error(f"Error adding DNS server: {e}")

    def remove_dns_server(self, server):
        """
        Remove a DNS server from the list.

        Args:
            server (str): The IP address of the DNS server.
        """
        try:
            self.dns_servers.remove(server)
        except Exception as e:
            logger.error(f"Error removing DNS server: {e}")


# Section 7: Monitor Class
class Monitor:
    def __init__(self):
        """
        Initialize the monitor.
        """
        self.query_count = 0
        self.error_count = 0
        self.start_time = time.time()

    def log_query(self, query):
        """
        Log a DNS query.

        Args:
            query (str): The query to log.
        """
        try:
            logger.info(f"Query: {query}")
            self.query_count += 1
        except Exception as e:
            logger.error(f"Error logging query: {e}")

    def log_error(self, error):
        """
        Log an error.

        Args:
            error (str): The error to log.
        """
        try:
            logger.error(f"Error: {error}")
            self.error_count += 1
        except Exception as e:
            logger.error(f"Error logging error: {e}")

    def get_stats(self):
        """
        Get statistics about the DNS server.

        Returns:
            dict: A dictionary containing statistics about the DNS server.
        """
        try:
            uptime = time.time() - self.start_time
            return {
                "query_count": self.query_count,
                "error_count": self.error_count,
                "uptime": uptime
            }
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return None
# Section 8: Advanced DNS Server Class
class AdvancedDNSServer:
    def __init__(self):
        """
        Initialize the advanced DNS server.
        """
        self.resolver = dns.resolver.Resolver()
        self.load_balancer = LoadBalancer(['8.8.8.8', '8.8.4.4'])
        self.cache = Cache()
        self.rate_limiter = RateLimiter(max_requests=100, time_window=60)
        self.ip_blacklist = IPBlacklist()
        self.monitor = Monitor()

    def handle_query(self, query, ip_address):
        """
        Handle a DNS query.

        Args:
            query (str): The query to handle.
            ip_address (str): The IP address of the client.

        Returns:
            The response to the query.
        """
        try:
            # Check if the IP address is blacklisted
            if self.ip_blacklist.is_blacklisted(ip_address):
                return None

            # Check if the query is rate limited
            if not self.rate_limiter.is_allowed(ip_address):
                return None

            # Check if the query is cached
            cached_response = self.cache.get(query)
            if cached_response:
                return cached_response

            # Get the DNS server from the load balancer
            dns_server = self.load_balancer.get_dns_server()
            if not dns_server:
                return None

            # Resolve the query
            self.resolver.nameservers = [dns_server]
            response = self.resolver.resolve(query, 'A')

            # Cache the response
            self.cache.set(query, response)

            # Log the query
            self.monitor.log_query(query)

            return response
        except Exception as e:
            self.monitor.log_error(str(e))
            return None

        # Section 9: Starting the DNS Server
        def start_dns_server(self):
            """
            Start the DNS server.
            """
            try:
                # Create a UDP socket
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                server_socket.bind(('localhost', 53))

                logger.info("DNS server started")

                while True:
                    try:
                        # Receive a query
                        data, address = server_socket.recvfrom(1024)
                        query = dns.message.from_wire(data)

                        # Handle the query
                        response = self.handle_query(str(query.question[0].name), address[0])
                        if response:
                            # Send the response
                            response_message = dns.message.make_response(query)
                            response_message.answer.append(response)
                            server_socket.sendto(response_message.to_wire(), address)
                        else:
                            # Send an error response
                            response_message = dns.message.make_response(query)
                            response_message.set_rcode(dns.rcode.SERVFAIL)
                            server_socket.sendto(response_message.to_wire(), address)
                    except KeyboardInterrupt:
                        logger.info("Shutting down DNS server")
                        break
                    except Exception as e:
                        logger.error(f"Error handling query: {e}")
            except Exception as e:
                logger.error(f"Error starting DNS server: {e}")
  
       if __name__ == '__main__':
    dns_server = AdvancedDNSServer()
    if args.child:
        # Run in child mode
        print("Running in child mode")
        # You can add custom logic here for child mode
        dns_server.start_dns_server()
    else:
        # Run in normal mode
        dns_server.start_dns_server()


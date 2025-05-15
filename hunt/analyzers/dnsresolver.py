import dns.resolver
import dns.reversename
from hunt.models import AbstractAnalyzer
import logging
from datetime import datetime
import json

class Dnsresolver(AbstractAnalyzer):
    """
    A child class that extends the functionality of APIClientBase to make request to forward dns and reverse dns
    """
    def __init__(self, ioctype:str, observable: str, task_id: str):
        super().__init__(analyzer_name="dnsresolver") # must replace by uuid
        self.ioctype = ioctype
        self.observable = observable
        self.task_id = task_id    
            
    def _get_forward_dns(self, domain, task_id):
        now = datetime.utcnow()
        timestamp_iso = now.strftime('%Y-%m-%dT%H:%M:%S') + 'Z'
        # Create a resolver object
        resolver = dns.resolver.Resolver()
        # Set Cloudflare's DNS server as the nameserver
        resolver.nameservers = ['1.1.1.1']
        # List of record types to query
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR']
        dns_records = {}
               
        try:
            for record_type in record_types:
                try:
                    # Perform the DNS lookup for each record type
                    answer = resolver.resolve(domain, record_type)
                    
                    # Create a list for this record type if not already present
                    if record_type not in dns_records:
                        dns_records[record_type] = []
                    
                    # Append records to the dictionary under the appropriate key
                    for record in answer:
                        if record_type == 'MX':
                            # Convert MX record dns_records to JSON-serializable format
                            dns_records[record_type].append({
                                "priority": record.preference,
                                "exchange": str(record.exchange)  # Convert Name object to string
                            })
                        elif record_type == 'SOA':
                            # Convert SOA record dns_records to JSON-serializable format
                            dns_records[record_type].append({
                                "mname": str(record.mname),  # Convert Name object to string
                                "rname": str(record.rname),  # Convert Name object to string
                                "serial": record.serial,
                                "refresh": record.refresh,
                                "retry": record.retry,
                                "expire": record.expire,
                                "minimum": record.minimum
                            })
                        else:
                            # Convert all other records to strings
                            dns_records[record_type].append(str(record))
                except dns.resolver.NoAnswer:
                    dns_records[record_type] = ["No answer."]
                except dns.resolver.NXDOMAIN:
                    dns_records[record_type] = ["Domain does not exist."]
                except dns.resolver.Timeout:
                    dns_records[record_type] = ["Query timed out."]
                except Exception as e:
                    dns_records[record_type] = [f"An error occurred: {e}"]
        except Exception as e:
            dns_records["General"] = [f"General error: {e}"]
    
        data = {
            "ts": timestamp_iso,
            "observable": domain,
            "rawData": dns_records,
            "meta": {
                "taskId": task_id,
                "analyzerName": self.analyzer_name,
            },
        }
        
        # Serialize to JSON and load data to the database
        return self.superDB_client.load_data_to_branch(
            self.poolname,
            "main",
            json.dumps(data, indent=4)
        )

    def _get_reverse_dns(self, ip, task_id):
        now = datetime.utcnow()
        timestamp_iso = now.strftime('%Y-%m-%dT%H:%M:%S') + 'Z'
        # Create a resolver object
        resolver = dns.resolver.Resolver()
        # Set Cloudflare's DNS server as the nameserver
        resolver.nameservers = ['1.1.1.1']
        # List of record types to query
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR']
        dns_records = {}                
        try:
            # Convert the IP address to a reverse DNS name
            reverse_name = dns.reversename.from_address(ip)
            
            # Perform the reverse DNS lookup
            answer = resolver.resolve(reverse_name, 'PTR')
            
            # Store the PTR results in the dictionary
            dns_records[ip] = [str(ptr) for ptr in answer]
        except dns.resolver.NXDOMAIN:
            dns_records[ip] = ["No PTR record found (NXDOMAIN)."]
        except dns.resolver.Timeout:
            dns_records[ip] = ["Query timed out."]
        except dns.resolver.NoAnswer:
            dns_records[ip] = ["No answer."]
        except Exception as e:
            dns_records[ip] = [f"An error occurred: {e}"]    
            
        data = {
            "ts": timestamp_iso,
            "observable": ip,
            "rawData": dns_records,
            "meta": {
                "taskId": task_id,
                "analyzerName": self.analyzer_name,
            },
        }        
        # Serialize to JSON and load data to the database
        return self.superDB_client.load_data_to_branch(
            self.poolname,
            "main",
            json.dumps(data, indent=4)
        )             
                          
    def execute(self):
        commits = []    
        if self.ioctype == 'domains':
            commits.append(self._get_forward_dns(self.observable, self.task_id))   
        if self.ioctype == 'ipv4s':
            commits.append(self._get_reverse_dns(self.observable, self.task_id))        
        result = [{"taskid": self.task_id, "commits": commits}]
        return result
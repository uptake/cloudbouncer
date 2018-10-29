# cloudbouncer/network-map
The network-map enumerates networking constructs within AWS and builds a logical model that can be used for evaluating patterns of connectivity and debugging specific connectivity problems.

Written in Python 2.7, using the AWS Python SDK Boto3

Scripts are invoked as command line tools using docopts argument parsing, ex `./network-map trace 8.8.8.8 10.1.1.2 --target_port=443 --sgs --flowlogs=prefix --accounts=dev`

`--help` for any script will give you a list of the arguments, syntax, assumptions, limitations, and examples

Dependencies are:- python 2.7
- boto3 `pip install boto3`
- docopts `pip install docopts`
- netaddr `pip install netaddr`
- dnspython `pip install dnspython`

## Design
First, the network map describes the major networking constructs in each targeted account in all regions, including VPCs, subnets, load balancers, route tables, network access control lists, elastic IPs, and VPC peering connections. It iterates over each subnet and builds a map of every other subnet that it can connect to.  This network map is written to the file 'results/network-map-YYYY-MM-DD.txt' for additional analysis if needed.

If you want to evaluate connectivity to other networks outside of the listed AWS accounts, modify the 'config.txt' file to include all external networks you want to include in the map.

The trace function for debugging network connectivity traces the approximate path a packet will take between two objects and evaluating whether all network configurations in between allow or block this packet.  It can check connectivity either very broadly (subnet to subnet) or very granularly (instance to instance/LB/etc). It evaluates the relevant NACLs, SGs, routes, gateways, etc to see if traffic can pass successfully.  It is used primarily for VPC <> VPC connecivity, but has support for internet facing traffic (both inbound and outbound), and can evaluate the AWS side of other private networks <> VPCs.   It has no support for any non-AWS network constructs, so if you have 3rd party firewalls / routers / etc you route your AWS traffic through, you will need to extend it.

## Limitations / Assumptions:
This only evaluates IPv4 constructs / addresses, and will not work for IPv6.

The port evaluation is currently limited to TCP, and would need to be extended for other protocols.

The response port is a randomly generated port between 1024-65535 to simulate the broadest range of linux socket response ports.  If you have a more granular response pattern you want to test, feel free to change it in the 'trace' function.

If you use a reverse proxy for internet-facing DNS, this tool will not work to test inbound internet traffic without modifications that unmask the next hop.  Uptake's private version has this for Cloudflare. 

If you want to check flowlogs, you need VPC flowlogs turned on for the VPC and writing to a CloudWatch Log Group.  You must specify the prefix
for your log group, for example, the 'vpcflowlogs' in a log group: 'vpcflowlogs/vpc-123456789'.  This tool will download the last hour of relevant flowlogs for these IP addresses and check their status.  This may take several minutes depending on volume of traffic

This script assumes broad read-only or admin-level credentials in each targeted account.  It does not do any write operations.  

## Trace function details
This network map is designed to serve as a logical model for how AWS actually evaluates your traffic, so it has the logic to parse the various constructs as follows:

Routes - in the case of overlapping routes, AWS evaluates the routes used from least permissive to most, with the exception being that it prefers local routes (within the same VPC) over any propagated routes. The network map evaluates all routes to determine which is prioritized and outputs that in the results.  See [VPC Route Priority](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html) and [VPN Route Priority](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_VPN.html#vpn-route-priority) for more details.  Trace also warns when you have asymmetric routes on either side of the connection (for example, one using VPC peering but the other side pointing to a direct connect / virtual gateway)

Network access control lists - we evaluate the NACLs in in ascending rule order until the first match is found.  The specific matched rule is output. For AWS <> AWS connections, all four relevant NACLs are evaluated: egress from source subnet, ingress to target subnet, egress from target for response traffic, and ingress to source for response traffic.

Security Groups - if you are checking instance-level granularity connectivity and specify the --sgs flag, it finds the ENI corresponding to this IP address and evaluates all security groups attached to that ENI to see if the SG rules allow this traffic.  If any rule allows the traffic, it returns the specific rule that first matched.  There may be additional rules that would also allow this traffic, so if you are using the network-map to check that a specific pattern is prevented, make sure to test after each AWS resource change.

Ports - if you do not specify a `--target_port=X` in your trace function, the network map assumes that you want to test all TCP ports for unrestricted network traffic.  Target_port currently only supports testing one port at a time.

Load Balancers -  supports ELBsv1 and ELBsv2 including application and network load balancers. When a load balancer is detected, it finds the targets of the laod balancer, and then evaluates the network configuration hops between the LB and the target for each possible target.  It does not evaluate any non-AWS load balancers (for example, if you have a K8S LB after an ELB), because there is no way for the network map to determine what those hops are.


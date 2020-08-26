from netaddr import IPNetwork

def generate_ips(num, prefix, exclude_ips):
    """ Generate random ips within prefix """
    prefix = IPNetwork(prefix)
    exclude_ips.append(prefix.broadcast)
    exclude_ips.append(prefix.network)
    available_ips = list(prefix)

    if len(available_ips) - len(exclude_ips)< num:
        raise Exception("Not enough available IPs")

    generated_ips = []
    for available_ip in available_ips:
        if available_ip not in exclude_ips:
            generated_ips.append(str(available_ip) + '/' + str(prefix.prefixlen))
        if len(generated_ips) == num:
            break

    return generated_ips

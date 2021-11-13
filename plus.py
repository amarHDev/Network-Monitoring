def getProtocole(name):
    # Extract all protocoles used by file pcap
    count_protocol={}
    num_line = 2
    with open(name,'r') as f:
        lines = f.readlines()[num_line-1:]
        for line in lines:
            proto=line.split(",")[10]
            if proto not in count_protocol:
                count_protocol[proto]=1
            else:
                count_protocol[proto]+=1
        return count_protocol 

print(" 2) Les protocles uilisées ainsi que le nombre de paquets associés à chaque protocole ( voir le plot pour mieux visualiser) : \n")
table = {num:name[8:] for name,num in vars(socket).items() if name.startswith("IPPROTO")}#utilisé par import socket
for k,v in getProtocole(path).items():
    val_int = int(k) 
    print(" Protocole : ",socket.getservbyport(val_int), " ==> ",v," paquet(s)")
    #print(" Protocole : ",k, " ==> ",v," paquet(s)")






def getNameProtocole(name):
    # permet d'extraire tout les protcoles utilisés dans ce fichier pcap 
    count_protocol={}
    num_line = 2
    with open(name,'r') as f:
        lines = f.readlines()[num_line-1:]
        for line in lines:
            category_protocole=line.split(",")[30]
            if(category_protocole == '"Network"'):
                proto=line.split(",")[29]
                if proto not in count_protocol:
                    count_protocol[proto]=1
                else:
                    count_protocol[proto]+=1
        return count_protocol 


#for k,v in getNameProtocole(path).items():
#    print(" Protocole : ",k, " ==> ",v," paquet(s)")
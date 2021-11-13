from scapy.all import * #Pour l'etudes des paquets réseaux
import pyx #Package pour la création de PostScript, PDF, and SVG files.
import matplotlib.pyplot as plt
import numpy as np
from scapy.all import sniff

#---------------- Graph section ----------
from collections import namedtuple
from pyvis.network import Network
import networkx as nx
#-----------------------------------------

import nfstream
from nfstream import NFStreamer, NFPlugin
import pandas as pd
pd.set_option('display.max_columns', 500)
pd.set_option('display.max_rows', 500)

import socket #Pour faire le lien entre les noms des protocoles et leurs

flows_count = NFStreamer(source='group-9-19.pcap').to_csv(path=None,
                                                        flows_per_file=0,
                                                        columns_to_anonymize=[])

data_file = rdpcap('group-9-19.pcap') #lecture du fichier pcap avec scapy
path="group-9-19.pcap.csv"

#----------------------------- General informations -------------------------------------------------------
def getNumberPacket(name):
    # Return number of packets in Network trafic 
    nbr_paquets = 0
    for line in open(name,'r').readlines():
        nbr_paquets+=1
    return nbr_paquets

print("\n --- Debut de l'analyse du fichier pcap ---\n ")
print("Le nombre de paquets présents dans le fichier est : ",getNumberPacket(path)," Paquets")

#----------------------------- Communication protocols used in transport layer ---------------------------
print("\n 1) Les noms des protocoles de communications présent dans le fichier (voir le plot pour mieux visualiser) ")
print("Not yet communication protocol")
def getCommProtocol():
    print("")
def plotVerticalHistogramme(function,title):
    keys_data = list()
    vals_data = list()
    for key in function.keys():
        keys_data.append(key)
   
    for key in function.keys() :
        vals_data.append(function[key])
    
    plt.style.use('ggplot')
    plt.barh(keys_data,vals_data)
    plt.title(title)
    plt.xlabel('Nombres de paquets transmis')
    plt.ylabel('Protocoles names')

#plotVerticalHistogramme(getCommProtocol(),"Les protocles de communications utilisés")
#plt.show()









#----------------------------- Application protocols used  ---------------------------
print("\n 2) Les noms des protocoles de niveau applications utilisés (voir le plot pour mieux visualiser) ")
def getProtocolApplication(name):
    # permet d'extraire tout les protcoles utilisés dans ce fichier pcap 
    count_protocol={}
    num_line = 2
    with open(name,'r') as f:
        lines = f.readlines()[num_line-1:]
        for line in lines:
            #category_protocole=line.split(",")[30]
            #if(category_protocole == '"Web"'):
                proto = line.split(",")[29]
                if not "." in proto:
                    if not "_" in proto:
                        if proto not in count_protocol:
                            count_protocol[proto]=1
                        else:
                            count_protocol[proto]+=1
        return count_protocol 

for k,v in getProtocolApplication(path).items():
    print(" Protocole : ",k, " ==> ",v," paquet(s) ")
plotVerticalHistogramme(getProtocolApplication(path),"Used application protocoles")
plt.show()












#-------------------- Who is sending/receiving data? What are their MAC addresses? -----------------------------------
# -------------- Graph section ------------------------------------------------------------------------
print("\n 3) Les IP qui envoi ou reçoit des données ainsi que leurs adresses mac (voir le plot pour mieux visualiser) ")
def getSenderReceiverData(name):
    # permet d'extraire tout les adresse IP qui trasmette une information
    count_protocol={}
    num_line = 2
    cptSource = 0
    cptReceive = 0
    with open(name,'r') as f:
        lines = f.readlines()[num_line-1:]
        for line in lines:
                adrSource=line.split(",")[2]
                cptSource = cptSource + 1
                count_protocol[cptSource] = adrSource
        cptReceive = 9999999999
        count_protocol[cptReceive] = cptReceive
        for line in lines:
                adrReceive=line.split(",")[6]
                cptReceive = cptReceive + 1
                count_protocol[cptReceive] = adrReceive
        
                
        return count_protocol 
    
def getMacSender(name):
    # permet d'extraire 
    count_protocol={}
    num_line = 2
    with open(name,'r') as f:
        lines = f.readlines()[num_line-1:]
        for line in lines:
                adrSource=line.split(",")[2]
                if adrSource not in count_protocol:
                    adrMacSource=line.split(",")[3]
                    count_protocol[adrSource] = adrMacSource
                
        return count_protocol 

def getMacReceiver(name):
    # permet d'extraire 
    count_protocol={}
    num_line = 2
    with open(name,'r') as f:
        lines = f.readlines()[num_line-1:]
        for line in lines:
                adrReceive=line.split(",")[6]
                if adrReceive not in count_protocol:
                    adrMacReceive=line.split(",")[7]
                    count_protocol[adrReceive] = adrMacReceive
                
        return count_protocol 

SenderReceiverIP = getSenderReceiverData(path)
macSender = getMacSender(path)
macReceiver = getMacReceiver(path)

#Return liste d'adjacence
def adjacency_dict(graph):
    adj = {node: [] for node in graph.nodes}
    for edge in graph.edges:
        node1, node2 = edge[0], edge[1]
        adj[node1].append(node2)
        if not graph.is_directed:
            adj[node2].append(node1)
    return adj

#Return the adjacency matrix od the graph
def adjacency_matrix(graph):
    adj = [[0 for node in graph.nodes] for node in graph.nodes]
    for edge in graph.edges:
        node1, node2 = edge[0], edge[1]
        adj[node1][node2] += 1
        if not graph.is_directed:
            adj[node2][node1] += 1
    return adj

def show(graph, output_filename,title_mac):
    g = Network(directed = graph.is_directed, height='750px', width='100%', bgcolor='#222222', font_color='white')
    g.barnes_hut()
    g.add_nodes(graph.nodes,title=title_mac)
    g.add_edges(graph.edges)
   
    g.show_buttons(filter_=['nodes'])
    g.show(output_filename)
    return g

def plotNetworkGraph(SenderReceiverIP,dicSender,dicReceiver):

    nodes = list(dicSender.keys())
    
    for i in list(dicReceiver.keys()):
        nodes.append(i)
    #print("len",len(nodes))
    #Create a list of tuples from dictionnary
    edges = []
    positionStop = 9999999999

    listSenders = []
    listReceiver = []
    for x,y in SenderReceiverIP.items():
        if(x < 9999999999):
            listSenders.append(y)

    for x,y in SenderReceiverIP.items():
        if(x > 9999999999):
            listReceiver.append(y)
    edges = list(zip(listSenders, listReceiver)) #fusionner deux listes dans une liste de tuples
    #print("lenSender",len(listSenders))
    #print("lenReceiver",len(listReceiver))
    #print(edges)
    listMacSenderReceiver = []
    for x,y in dicSender.items():
         listMacSenderReceiver.append(y)
    for x,y in dicReceiver.items():
         listMacSenderReceiver.append(y)

    #---------------- Display on Console ---------------------------
    for x in edges:  
        print(x[0] , "------>" , x[1] )
    
    Graph = namedtuple("Graph",["nodes","edges","is_directed"])
    G = Graph(nodes, edges, is_directed=True)
    show(G, "basic.html",listMacSenderReceiver)

plotNetworkGraph(SenderReceiverIP,macSender,macReceiver)












#-------------------------------- Traffic volume per time, incoming and outgoing flows ------------------------------
print("\n 4) volume du trafic - incoming and outgoing flows (voir le plot pour mieux visualiser) ")
print("Not yet communication protocol")















#---------------------------------------- Who (what IP address) is sending more volume of traffic? -----------------------
print("\n 5) Les top ip sources  dans le fichier pcap ( voir le plot pour mieux visualiser) : \n")

def topSources(name):
    # permet de compter de nombre de paquet utilisé par une source IP 
    count_source={}
    num_line = 2
    with open(name,'r') as f:
        lines = f.readlines()[num_line-1:]
        for line in lines:
            src=line.split(",")[2]
            if src not in count_source:
                count_source[src]=1
            else:
                count_source[src]+=1
        #print(count_source)
        #print(type(count_source))
        return count_source 

def plotHorizantalHistogramme(function,title):
  plt.style.use('ggplot')
  # permet de faire un affichege en histogramme
  print(function)
  pos = np.arange(len(function.keys()))
  width = 1.0     # gives histogram aspect to the bar diagram
  ax = plt.axes()
  ax.set_xticks(pos + (width /25))
  ax.set_xticklabels(function.keys())

  plt.bar(list(function.keys()), function.values(), color='g')
  plt.title(title)  
  plt.xlabel("Adresses IP")
  plt.ylabel("Paquets transmit") 

for k,v in topSources(path).items():
    print(" IP source : ",k, " ==> ",v," paquet(s)")

plotHorizantalHistogramme(topSources(path),"Top des IP sources")
plt.show()










#----------------------------------------------------------------------------------------------
# ----------------------- 3 other plots you consider relevant ---------------------------------
#----------------------------------------------------------------------------------------------









#------------------- First other plot ---------------------------------------------------------
print("\n 6) Details d'un paquet en vesion pdf : (pour une représentation plus lisible) \n")

def showDetailPaquet(id):
    return data_file[id].show()

def DetailPaquetToPdf(id):
    # transforme les proprietes d'un paquet en pdf avec un show plus lisible et facile à interpreter ( voir dans le rapport un exemple )
    data_file[id].pdfdump('paquet.pdf')
    print("Paquet enregistré en pdf ")
    print("Attention : cette fonction à enregistré le fichier dans la racine de votre dossier personnel selon votre OS")

print("\n6) Les proprietées d'un paquet :\n")
showDetailPaquet(114)

DetailPaquetToPdf(0)















#------------------- Second other plot ---------------------------------------------------------

def plotTestPassedOrNot(name,passedList):
    num_line = 2
    passedList = tuple(passedList)
    taille  = len(passedList)
    taille = taille + 1
    
    testFailJustTestHaut = 0
    testFailJustTestBas = -120
    passedListList = list(passedList) 
    passedListList.append(testFailJustTestHaut)
    passedList = tuple(passedListList)
    failedList = []
    failedListList = list(failedList)
    for x in range(taille-1): 
        failedListList.append(0)
    failedListList.append(testFailJustTestBas)
    failedList = tuple(failedListList)
    #print("Len",taille)
    ind = np.arange(taille)    # the x locations for the groups
    width = 0.3  # the width of the bars: can also be len(x) sequence
    fig, ax = plt.subplots()

    p1 = ax.bar(ind, passedList, width, label='Tests Passed',color=['green'])
    p2 = ax.bar(ind, failedList, width, bottom=passedList, label='Tests Failed',color=['red'])

    ax.axhline(0, color='grey', linewidth=0.8)
    ax.set_ylabel('packets')
    ax.set_xlabel('Tests')
    ax.set_title('Test Passed or Not for DNS with UDP')
    ax.set_xticks(ind)
    ax.tick_params(axis='x', colors='white')
    #ax.set_xticklabels(('G1', 'G2', 'G3', 'G4', 'G5'))
    ax.legend()

print("\n 7) Les paquest DNS doivent tous être inférieur à 512 dans le cas d'UDP (Règle fonctionnelles) \n")
def verifeLenPaquetDns():
    print("testing ...")
    test=""
    passedList = []
    for i in data_file:
        if i.haslayer("DNS"):
            if i.len>512:
                test="failed"
                passedList.append(i.len*(-1))
            else:
                passedList.append(i.len)
     
    #print("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",failedList)      
    #print("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",passedList)   
    if test!="failed":
        print("Test passed \nTout les paquets sont de taille inférieure à 512 ")
        print("end testing.")
    else:
        print("Test not passed ! there are something wrong")
    
    plotTestPassedOrNot(path,passedList)

print('hahahahahhahahahahahahah')
verifeLenPaquetDns()
plt.show()
















#------------------- Third other plot ---------------------------------------------------------













def plotCircle(function,title):
    # permet de faire un affichege en cercle 
    data=function(path)
    labels=[]
    size=[]
    for i in data:
        labels.append(i)
        size.append(int(data[i]))
    size_pourcentage=[]
    somme=sum(size)
    for i in size:
        size_pourcentage.append(round((i/somme)*100,2))
    fig1, ax1 = plt.subplots()
    explode=[]
    for i in size_pourcentage:
        explode.append(0.05)
    ax1.pie(size, startangle=90,autopct='%1.1f%%',explode=explode)
    ax1.legend(labels=labels)
    plt.title(title)




    








def topProtocole(name):
    # permet de compter de nombre de paquet utilisé par une source IP 
    count_source={}
    num_line = 2
    with open(name,'r') as f:
        lines = f.readlines()[num_line-1:]
        for line in lines:
            src=line.split(",")[10]
            if src not in count_source:
                count_source[src]=1
            else:
                count_source[src]+=1
       
        protocole_val_max = max(count_source.items(), key = lambda x: x[1])
        return protocole_val_max 

def AffichageQuery():
    # permet de voir les échanges client seveur et les réponses 
    src_dnsServer_names={}
    for i in data_file:
        query="DNS Qry"
        if i.haslayer("DNS"):
            if query in i.summary():
                ip_src=i["IP"].src
                ip_dst=i["IP"].dst
                name=i.qd.qname
                if ip_src not in src_dnsServer_names:
                    src_dnsServer_names[ip_src]=[[ip_dst],[name]]
                else:
                    src_dnsServer_names[ip_src][0].append(ip_dst)
                    src_dnsServer_names[ip_src][1].append(name)
                    new_dst=list(set(src_dnsServer_names[ip_src][0]))
                    new_name=list(set(src_dnsServer_names[ip_src][1]))
                    src_dnsServer_names[ip_src]=[new_dst,new_name]
    for k,v in src_dnsServer_names.items():
        print("Le client ", k,"\n\nA interrogé le(s) dns serveur : ",v[0], "\n\nPour avoir les IP des noms de domaines suivants :\n")
        for i in v[1]:
            print("- ",i)












print("\n 7) Affichage des requêtes clients , leur dns serveur et les noms des ip demandés : \n")
AffichageQuery()





#plotCircle(getNameProtocole,"Les protocoles utilisées")
#plt.show()
######plotCircle(topSources,"Top des IP sources")



#Potocole max used
def maxIPSending(function):
    #print(function)
    max_val = max(function.items(), key = lambda x: x[1])

    #Max key seulement
    #max_key = max(function, key = function.get)
    #print(max_key)
    print(max_val)
    
packets = sniff(offline='group-9-19.pcap')   
print("aaaaaa", packets)
maxIPSending(topSources(path))
'''
for x in range(len(topProtocole(path))):
    
    if(x == 0 ):
        val_int = int(topProtocole(path)[x]) 
        print(" Protocole max used: ", socket.getservbyport(val_int), " ==> ", end = '')
    elif(x == 1):
        print(topProtocole(path)[x]," paquet(s)")
'''
#IP max sending more Information

print("end executing ")



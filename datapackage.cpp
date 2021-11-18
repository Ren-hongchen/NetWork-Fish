#include "datapackage.h"
#include <QMetaType>
#include "winsock2.h"

DataPackage::DataPackage()
{
    qRegisterMetaType<DataPackage>("DataPackage");
    this->timeStamp = "";
    this->data_length = 0;
    this->package_type = 0;
}

void DataPackage::setInfo(QString info){
    this->info = info;
}

void DataPackage::setPointer(const u_char *pkt_content,int size){
    this->pkt_content = (u_char*)malloc(size);
    memcpy((char *)(this->pkt_content),pkt_content,size);
}

void DataPackage::setTimeStmp(QString timeStamp){
    this->timeStamp = timeStamp;
}

void DataPackage::setPackageType(int type){
    this->package_type = type;
}

void DataPackage::setDataLength(u_int data_length){
    this->data_length = data_length;
}

QString DataPackage::getInfo() {
    return this->info;
}

QString DataPackage::getDataLength(){
    return QString::number(this->data_length);
}

QString DataPackage::getPackageType(){
    switch (this->package_type) {
        case 1: return "ARP";
        case 2: return "ICMP";
        case 3: return "TCP";
        case 4: return "UDP";
        case 5: return "DNS";
        case 6: return "TLS";
        case 7: return "SSL";
        default: return "";
    }
}

QString DataPackage::getTimeStmp(){
    return this->timeStamp;
}

QString DataPackage::byteToString(u_char *str, int size){
    QString res = "";
    for(int i=0;i<size;i++) {
        char one = str[i] >> 4;
        if(one >= 0x0A)
            one += 0x41-0x0A;
        else one += 0x30;

        char two = str[i] & 0xF;
        if(two >= 0x0A)
            two += 0x41-0x0A;
        else two += 0x30;

        res.append(one);
        res.append(two);
    }
    return res;
}

QString DataPackage::getDesMacAddr(){
    ETHER_HEADER *eth;
    eth = (ETHER_HEADER*)(pkt_content);
    u_char *addr = eth->ethernet_des_host;
    if(addr){
        QString res = byteToString(addr,1) + "."
           + byteToString((addr+1),1) + ":"
           + byteToString((addr+2),1) + ":"
           + byteToString((addr+3),1) + ":"
           + byteToString((addr+4),1) + ":"
           + byteToString((addr+5),1);
        if(res == "FF:FF:FF:FF:FF:FF") return "FF:FF:FF:FF:FF:FF(Broadcast)";
        else return res;
    }
    return "";
}


QString DataPackage::getSrcMacAddr(){
    ETHER_HEADER *eth;
    eth = (ETHER_HEADER*)(pkt_content);
    u_char *addr = eth->ethernet_src_host;
    if(addr){
        QString res = byteToString(addr,1) + "."
           + byteToString((addr+1),1) + ":"
           + byteToString((addr+2),1) + ":"
           + byteToString((addr+3),1) + ":"
           + byteToString((addr+4),1) + ":"
           + byteToString((addr+5),1);
        if(res == "FF:FF:FF:FF:FF:FF") return "FF:FF:FF:FF:FF:FF(Broadcast)";
        else return res;
    }
    return "";
}

QString DataPackage::getDesIpAddr(){
    IP_HEADER *ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    sockaddr_in desAddr;
    desAddr.sin_addr.s_addr = ip->des_addr;
    return QString(inet_ntoa(desAddr.sin_addr));
}

QString DataPackage::getSrcIpAddr(){
    IP_HEADER *ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    sockaddr_in srcAddr;
    srcAddr.sin_addr.s_addr = ip->src_addr;
    return QString(inet_ntoa(srcAddr.sin_addr));
}

QString DataPackage::getSource(){
    if(this->package_type == 1){
        return this->getSrcMacAddr();
    }
    return this->getSrcIpAddr();
}

QString DataPackage::getDestination(){
    if(this->package_type == 1){
        return this->getDesMacAddr();
    }
    return this->getDesIpAddr();
}

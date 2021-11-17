#include "datapackage.h"
#include <QMetaType>

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
    this->pkt_content = pkt_content;
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

QString DataPackage::byteToString(char *str, int size){
    QString res = "";
    for(int i=0;i<size;i++) {
        char one = str[i] >> 4;
        if(one > 0x0A)
            one += 0x41-0x0A;
        else one += 0x30;

        char two = str[i] & 0xF;
        if(two > 0x0A)
            two += 0x41-0x0A;
        else two += 0x30;

        res.append(one);
        res.append(two);
    }
    return res;
}

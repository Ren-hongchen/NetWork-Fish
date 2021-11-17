#include "multhread.h"
#include <QDebug>
#include "Format.h"
#include "datapackage.h"

multhread::multhread()
{
    this->isDone = true;
}

bool multhread::setPointer(pcap_t *pointer) {
    this->pointer = pointer;
    if(pointer)
        return true;
    return false;
}

void multhread::setFlag() {
    this->isDone = false;
}

void multhread::resetFlag() {
    this->isDone = true;
}

void multhread::run() {
    while(true) {
        if(isDone)
            break;
        else {
            int res = pcap_next_ex(pointer,&header,&pkt_data);
            if(res == 0)
                continue;
            local_time_sec = header->ts.tv_sec;
            localtime_s(&local_time,&local_time_sec);
            strftime(timeString,sizeof(timeString),"%H:%M:%S",&local_time);
            QString info = "";
            int type = ethernetPackageHandle(pkt_data,info);
            if(type){
                DataPackage data;
                int len = header->len;
                data.setInfo(info);
                data.setDataLength(len);
                data.setTimeStmp(timeString);
                emit send(data);
            }
        }
    }
}

int multhread::ethernetPackageHandle(const u_char *pkt_content, QString &info){
    ETHER_HEADER *ethernet;
    u_short content_type;
    ethernet = (ETHER_HEADER *)(pkt_content);
    content_type = ntohs(ethernet->type);
    switch (content_type) {
        case 0x0800: { //ip
            info = "ip";
            return 1;
        }
        case 0x0806: { //arp
            info = "arp";
            return 1;
        }
        default:break;
    }
    return 0;
}

#ifndef DATAPACKAGE_H
#define DATAPACKAGE_H
#include "Format.h"
#include <QString>

class DataPackage
{
public:
    DataPackage();
    void setDataLength(u_int data_length);
    void setTimeStmp(QString timeStamp);
    void setPackageType(int type);
    void setPointer(const u_char *pkt_content,int size);
    void setInfo(QString info);

    QString getDataLength();
    QString getTimeStmp();
    QString getPackageType();
    QString getInfo();
    QString getSource();
    QString getDestination();

    QString getDesMacAddr();
    QString getSrcMacAddr();

    QString getDesIpAddr();
    QString getSrcIpAddr();

public:
    const u_char *pkt_content;
protected:
    static QString byteToString(u_char *str,int size);
private:
    u_int data_length;
    QString timeStamp;
    QString info;
    int package_type;
};

#endif // DATAPACKAGE_H

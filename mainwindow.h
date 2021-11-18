#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "pcap.h"
#include "winsock2.h"
#include "datapackage.h"
#include <QVector>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void showNetworkCard();
    int capture();
private slots:
    void on_comboBox_currentIndexChanged(int index);

public slots:
    void HandleMessage(DataPackage data);

private:
    Ui::MainWindow *ui;
    pcap_if_t *all_devices; //指向所有设备
    pcap_if_t *device;  //指向当前设备
    pcap_t *pointer; //打开设备的描述符
    QVector<DataPackage> pData;
    int countNumber;
    char errbuf[PCAP_ERRBUF_SIZE];  //存放错误信息
};
#endif // MAINWINDOW_H

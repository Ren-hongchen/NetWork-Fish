#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QString>
#include "multhread.h"
#include <QDebug>
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    statusBar()->showMessage("welcome to fish");
    countNumber = 0;


    ui->toolBar->addAction(ui->actionRun);
    ui->toolBar->addAction(ui->actionStop);
    ui->toolBar->addAction(ui->action_Clear);
    ui->toolBar->setMovable(false);


    ui->tableWidget->verticalHeader()->setDefaultSectionSize(30);
    ui->tableWidget->setColumnCount(7);
    QStringList title = {"NO.","Time","Source","Destination","Protocol","Length","Info"};
    ui->tableWidget->setHorizontalHeaderLabels(title);
    ui->tableWidget->setColumnWidth(0,50);
    ui->tableWidget->setColumnWidth(1,150);
    ui->tableWidget->setColumnWidth(2,200);
    ui->tableWidget->setColumnWidth(3,200);
    ui->tableWidget->setColumnWidth(4,150);
    ui->tableWidget->setColumnWidth(5,150);
    ui->tableWidget->setColumnWidth(6,1000);

    ui->tableWidget->setShowGrid(false);
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);



    showNetworkCard();
    multhread *thread = new multhread;
    static bool run = false;
    static bool stop = false;
    connect(ui->actionRun,&QAction::triggered,this,[=](){
        run = !run;
        if(run) {
            countNumber = 0;
            ui->tableWidget->clearContents();
            ui->tableWidget->setRowCount(0);

            int dataSize = this->pData.size();
            for(int i = 0;i<dataSize;i++){
                free((char*)(this->pData[i].pkt_content));
                this->pData[i].pkt_content = nullptr;
            }
            QVector<DataPackage>().swap(pData);

            int res = capture();
            if(res != -1 && pointer) {
                thread->setPointer(pointer);
                thread->setFlag();
                thread->start();
                ui->actionRun->setDisabled(true);
                ui->actionStop->setDisabled(false);
                ui->comboBox->setDisabled(true);
            } else {
                run = !run;
                countNumber = 0;
            }
        }
    });
    connect(ui->actionStop,&QAction::triggered,this,[=](){
        stop = !stop;
        if(stop) {
            thread->resetFlag();
            thread->quit();
            thread->wait();
            ui->actionStop->setDisabled(true);
            ui->actionRun->setDisabled(false);
            ui->comboBox->setDisabled(false);
            pcap_close(pointer);
            pointer = nullptr;
        }
    });

    connect(thread,&multhread::send, this,&MainWindow::HandleMessage);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::showNetworkCard()
{
    int n = pcap_findalldevs(&all_devices,errbuf);
    if(n == -1) {
        ui->comboBox->addItem("error: " + QString(errbuf));
    }
    ui->comboBox->clear();
    ui->comboBox->addItem("please choose card!");
    for(device = all_devices;device != nullptr;device = device->next) {
        QString device_name = device->name;
        device_name.replace("\\Device\\","");
        QString des = device->description;
        QString item = device_name + des;
        ui->comboBox->addItem(item);
    }
}

void MainWindow::on_comboBox_currentIndexChanged(int index)
{
    int i = 0;
    if(index != 0) {
        for(device = all_devices; i<index - 1; device = device->next,i++);
    }
    return;
}

int MainWindow::capture() {
    if(device) {
        pointer = pcap_open_live(device->name,65536,1,1000,errbuf);
    } else {
        return -1;
    }
    if(!pointer) {
        pcap_freealldevs(all_devices);
        device = nullptr;
        return -1;
    } else {
        if(pcap_datalink(pointer) != DLT_EN10MB) {
            pcap_close(pointer);
            pcap_freealldevs(all_devices);
            device = nullptr;
            pointer = nullptr;
            return -1;
        }
        statusBar()->showMessage(device->name);
    }
    return 0;
}

void MainWindow::HandleMessage(DataPackage data){
    ui->tableWidget->insertRow(countNumber);
    this->pData.push_back(data);
    QString type = data.getPackageType();
    QColor color;
    if(type == "TCP")
        color = QColor(216,191,216);
    else if(type == "UDP")
        color = QColor(144,238,144);
    else if(type == "ARP")
        color = QColor(238,238,0);
    else if(type == "DNS")
        color = QColor(255,255,224);
    else
        color = QColor(255,218,185);

    ui->tableWidget->setItem(countNumber,0,new QTableWidgetItem(QString::number(countNumber)));
    ui->tableWidget->setItem(countNumber,1,new QTableWidgetItem(data.getTimeStmp()));
    ui->tableWidget->setItem(countNumber,2,new QTableWidgetItem(data.getSource()));
    ui->tableWidget->setItem(countNumber,3,new QTableWidgetItem(data.getDestination()));
    ui->tableWidget->setItem(countNumber,4,new QTableWidgetItem(type));
    ui->tableWidget->setItem(countNumber,5,new QTableWidgetItem(data.getDataLength()));
    ui->tableWidget->setItem(countNumber,6,new QTableWidgetItem(data.getInfo()));

    for(int i = 0;i < 7; i++){
        ui->tableWidget->item(countNumber,i)->setBackgroundColor(color);
    }
    countNumber++;

}

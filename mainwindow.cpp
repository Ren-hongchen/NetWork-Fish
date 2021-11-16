#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QString>
#include "multhread.h"
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    showNetworkCard();
    multhread *thread = new multhread;
    static bool run = false;
    static bool stop = false;
    connect(ui->actionRun,&QAction::triggered,this,[=](){
        run = !run;
        if(run) {
            int res = capture();
            if(res != -1 && pointer) {
                thread->setPointer(pointer);
                thread->setFlag();
                thread->start();
                ui->actionRun->setDisabled(true);
                ui->actionStop->setDisabled(false);
                ui->comboBox->setDisabled(true);
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


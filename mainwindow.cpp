#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QString>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    showNetworkCard();
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


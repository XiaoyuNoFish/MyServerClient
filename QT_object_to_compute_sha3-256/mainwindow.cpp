#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QCryptographicHash>
#include<iostream>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    QCryptographicHash *process_passwd = new QCryptographicHash(QCryptographicHash::Sha3_256);
    process_passwd->reset();
    QString s("Lazy574839");
    QByteArray bytearray= s.toLocal8Bit();
    process_passwd->addData(bytearray,bytearray.size());
    bytearray = process_passwd->result();
    bytearray = bytearray.toBase64();
    std::cout<<std::string(bytearray)<<std::endl;
}

MainWindow::~MainWindow()
{
    delete ui;
}


#include "Widget.h"
#include <QApplication>
#include <QFileInfo>
#include <QDebug>

int main(int argc, char *argv[])
{
    if (argc<2)
    {
        qDebug()<<"Please input dir path!";
        return 0;
    }

    QString strDirPath = argv[1];
    if (!QFileInfo(strDirPath).exists())
    {
        qDebug()<<"The dir path isn't existed!";
        return 0;
    }

    QApplication a(argc, argv);
    Widget w(strDirPath);
    w.show();

    return a.exec();
}

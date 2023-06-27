#include "Widget.h"
#include "ui_Widget.h"

#include <QTableWidget>
#include <QFileSystemWatcher>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFontMetrics>
#include <QDebug>

void AdjustTableColumnWidth(QTableWidget& tableWidget, int column)
{
    // 调整列宽
    int maxWidth = 0;
    for (int row = 0; row < tableWidget.rowCount(); ++row)
    {
        QTableWidgetItem* item = tableWidget.item(row, column);
        if (item)
        {
            // 获取单元格内容
            QString text = item->text();

            // 获取字体度量
            QFontMetrics fontMetrics(tableWidget.font());

            // 获取文本的矩形边界
            QRect rect = fontMetrics.boundingRect(text);

            // 获取矩形的宽度
            int textWidth = rect.width();

            // 更新最大宽度
            maxWidth = qMax(maxWidth, textWidth);
        }
    }

    // 设置列宽
    tableWidget.setColumnWidth(column, maxWidth);
}

Widget::Widget(const QString& path, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);

    ui->tableWidget_WithJmp->horizontalHeader()->hide();
    ui->tableWidget_WithJmp->verticalHeader()->hide();
    ui->tableWidget_WithJmp->setShowGrid(false);
    ui->tableWidget_WithJmp->setSelectionBehavior(QAbstractItemView::SelectRows);

    m_strFilePathWithJmp         = path+"/AddrFlowEasyWithJmp.asm";
    m_strFilePathFlowDisasmCode  = path+"/AddrFlowEasy.asm";
    m_strFilePathRegsInformation = path+"/AddrFlow.json";

    m_pFileJmpDisasmCodeWatcher   = new QFileSystemWatcher(this);
    m_pFileFlowDisasmCodeWatcher  = new QFileSystemWatcher(this);
    m_pFileRegsInformationWatcher = new QFileSystemWatcher(this);
    m_pFileJmpDisasmCodeWatcher->addPath(m_strFilePathWithJmp);
    m_pFileFlowDisasmCodeWatcher->addPath(m_strFilePathFlowDisasmCode);
    m_pFileRegsInformationWatcher->addPath(m_strFilePathRegsInformation);

    connect(m_pFileJmpDisasmCodeWatcher, SIGNAL(fileChanged(const QString &path)), this, SLOT(on_watch_JmpDisasmCode_file(const QString &path)));
    connect(m_pFileFlowDisasmCodeWatcher, SIGNAL(fileChanged(const QString &path)), this, SLOT(on_watch_FlowDisasmCode_file(const QString &path)));
    connect(m_pFileRegsInformationWatcher, SIGNAL(fileChanged(const QString &path)), this, SLOT(on_watch_RegsInformation_file(const QString &path)));

    on_watch_JmpDisasmCode_file(m_strFilePathWithJmp);
    on_watch_FlowDisasmCode_file(m_strFilePathFlowDisasmCode);
    on_watch_RegsInformation_file(m_strFilePathRegsInformation);

    ui->tableWidget_WithJmp->installEventFilter(this);
}

Widget::~Widget()
{
    delete ui;
}


void Widget::on_tableWidget_WithJmp_clicked(const QModelIndex &index)
{
    QString strItemText = ui->tableWidget_WithJmp->item(index.row(), index.column())->text();
    if (strItemText.isEmpty())
    {
        return;
    }
    QString strAddrID = strItemText.section(" ", 0, 0);

    QListWidget* pListWidget = ui->listWidget_Flow;
    for (int i=0; i<pListWidget->count(); i++)
    {
        QString strLine = pListWidget->item(i)->text();
        QString strAddrIDItem = strLine.section(" ", 0, 0);
        if (strAddrIDItem == strAddrID)
        {
            // 将选中行滚动到可见范围的最上面
            pListWidget->scrollToItem(pListWidget->item(i), QAbstractItemView::PositionAtTop);
            // 如果选中行靠近后面的几行，滚动条滚动到最底部
            int rowCount = pListWidget->count();
            int visibleRows = pListWidget->viewport()->height() / pListWidget->sizeHintForRow(0);
            if (rowCount - i <= visibleRows)
            {
                pListWidget->scrollToBottom();
            }
            QListWidgetItem* selectedItem = pListWidget->item(i);
            pListWidget->setCurrentItem(selectedItem);
            break;
        }
    }

    on_watch_RegsInformation_file(m_strFilePathRegsInformation);
}

void Widget::on_watch_JmpDisasmCode_file(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        file.close();
        return;
    }

    QStringList codeLines;
    while (!file.atEnd())
    {
        QByteArray line = file.readLine();
        codeLines.append(line);
    }
    file.close();

    QTableWidget* pTableWidget = ui->tableWidget_WithJmp;
    pTableWidget->clearContents();
    pTableWidget->setColumnCount(2);
    pTableWidget->setRowCount(codeLines.count());
    for (int i=0; i<codeLines.count(); i++)
    {
        pTableWidget->setItem(i, 0, new QTableWidgetItem(codeLines[i]));
        if (m_mapJmpDisasmCodeComment.contains(i))
        {
            pTableWidget->setItem(i, 0, new QTableWidgetItem(m_mapJmpDisasmCodeComment[i]));
        }
    }

    // 调整列宽
    for (int column = 0; column < pTableWidget->columnCount(); ++column)
    {
        pTableWidget->resizeColumnToContents(column);
    }
    pTableWidget->setColumnWidth(1, 300);
}

void Widget::on_watch_FlowDisasmCode_file(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        file.close();
        return;
    }

    QStringList codeLines;
    while (!file.atEnd())
    {
        QByteArray line = file.readLine();
        codeLines.append(line);
    }
    file.close();

    QListWidget* pListWidget = ui->listWidget_Flow;
    pListWidget->clear();
    pListWidget->addItems(codeLines);
}

void Widget::on_watch_RegsInformation_file(const QString &path)
{
    QTableWidgetItem* pCurrentJumpItem = ui->tableWidget_WithJmp->currentItem();
    if (!pCurrentJumpItem)
    {
        return;
    }
    QString strItemText  = ui->tableWidget_WithJmp->currentItem()->text();
    if (strItemText.isEmpty())
    {
        return;
    }
    QString strAddrIDFmt = strItemText.section(" ", 0, 0);
    QString strAddrID    = strAddrIDFmt.mid(2, 10);


    QPlainTextEdit* pPlainTextEdit = ui->plainTextEdit_regs;

    // 读取JSON文件
    QFile jsonFile(path);
    if (!jsonFile.open(QIODevice::ReadOnly))
    {
        qDebug() << "Failed to open JSON file.";
        return;
    }

    // 将JSON文件内容读取到QByteArray中
    QByteArray jsonData = jsonFile.readAll();
    jsonFile.close();

    // 解析JSON数据
    QJsonParseError error;
    QJsonDocument jsonDoc = QJsonDocument::fromJson(jsonData, &error);

    if (error.error != QJsonParseError::NoError)
    {
        qDebug() << "Failed to parse JSON:" << error.errorString();
        return;
    }

    if (!jsonDoc.isArray())
    {
        qDebug() << "JSON document is not an array.";
        return;
    }

    // 获取JSON数组
    QJsonArray jsonArray = jsonDoc.array();

    // 遍历每个对象
    for (int i = 0; i < jsonArray.size(); ++i)
    {
        QJsonValue jsonValue = jsonArray.at(i);
        if (jsonValue.isObject())
        {
            // 获取对象
            QJsonObject jsonObj = jsonValue.toObject();

            // 提取IP值
            QString ip = jsonObj.value("IP").toString();
            qDebug() << "IP:" << ip;
            if (!ip.contains(strAddrID))
            {
                continue;
            }

            // 提取Regs对象
            QJsonObject regsObj = jsonObj.value("Regs").toObject();

            QString eax = regsObj.value("eax").toString();
            qDebug() << "eax:" << eax;

            QString ecx = regsObj.value("ecx").toString();
            qDebug() << "ecx:" << eax;

            QString edx = regsObj.value("edx").toString();
            qDebug() << "edx:" << eax;

            QString ebx = regsObj.value("ebx").toString();
            qDebug() << "ebx:" << eax;

            QString edi = regsObj.value("edi").toString();
            qDebug() << "edi:" << eax;

            QString esi = regsObj.value("esi").toString();
            qDebug() << "esi:" << eax;

            QString ebp = regsObj.value("ebp").toString();
            qDebug() << "ebp:" << ebp;

            QString esp = regsObj.value("esp").toString();
            qDebug() << "esp:" << esp;

            QString strShowInfor = QString("eax=%1\tecx=%2\tedx=%3\tebx=%4\tedi=%5\tesi=%6\tebp=%7\tesp=%8\t")
                    .arg(eax).arg(ecx).arg(edx).arg(ebx)
                    .arg(edi).arg(esi).arg(ebp).arg(esp);
            pPlainTextEdit->setPlainText(strShowInfor);


            // 提取Disasm值
            QString disasm = jsonObj.value("Disasm").toString();
            qDebug() << "Disasm:" << disasm;

            break;
        }
    }

}

bool Widget::eventFilter(QObject *obj, QEvent *event)
{
    if (event->type() == QEvent::KeyPress)
    {
        QKeyEvent *keyEvent = static_cast<QKeyEvent *>(event);
        if (keyEvent->key() == Qt::Key_Up
                || keyEvent->key() == Qt::Key_Down)
        {
            on_tableWidget_WithJmp_clicked(ui->tableWidget_WithJmp->currentIndex());
        }
    }
    return QWidget::eventFilter(obj, event); // 传递事件给原始的事件处理函数
}


#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QMap>

class QPlainText;
class QTableWidget;
class QFileSystemWatcher;

namespace Ui {
class Widget;
}

class Widget : public QWidget
{
    Q_OBJECT

public:
    explicit Widget(const QString& path, QWidget *parent = 0);
    ~Widget();

private slots:
    void on_tableWidget_WithJmp_clicked(const QModelIndex &index);
    void on_watch_JmpDisasmCode_file(const QString &path);
    void on_watch_FlowDisasmCode_file(const QString &path);
    void on_watch_RegsInformation_file(const QString &path);

private:
    void loadJmpDisasmCode();
    void loadFlowDisasmCode();
    void loadRegsInformation();

protected:
    bool eventFilter(QObject *obj, QEvent *event) override;

private:
    Ui::Widget *ui;

private:
    QFileSystemWatcher* m_pFileJmpDisasmCodeWatcher;
    QFileSystemWatcher* m_pFileFlowDisasmCodeWatcher;
    QFileSystemWatcher* m_pFileRegsInformationWatcher;
    QMap<int, QString>  m_mapJmpDisasmCodeComment;
    QString             m_strFilePathWithJmp;
    QString             m_strFilePathFlowDisasmCode;
    QString             m_strFilePathRegsInformation;
};

#endif // WIDGET_H

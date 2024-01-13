#include <QApplication>
#include <QMainWindow>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QDebug>
#include <QTimer>
#include <QFileDialog>
#include <QMessageBox>

#include <Windows.h>

enum class InjectResult
{
    NotFoundPid,
    Error,
    Sucessfully
};

InjectResult InjectDLL(const char* dll_path, DWORD pid)
{
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (process == NULL)
    {
        return InjectResult::NotFoundPid;
    }

    void* alloc_base_addr = VirtualAllocEx(process, NULL, strlen(dll_path) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (alloc_base_addr == NULL)
    {
        CloseHandle(process);
        return InjectResult::Error;
    }

    if (!WriteProcessMemory(process, alloc_base_addr, dll_path, strlen(dll_path) + 1, NULL))
    {
        VirtualFreeEx(process, alloc_base_addr, 0, MEM_RELEASE);
        CloseHandle(process);
        return InjectResult::Error;
    }

    HMODULE kernel32_base = GetModuleHandle(L"kernel32.dll");
    if (kernel32_base == NULL)
    {
        VirtualFreeEx(process, alloc_base_addr, 0, MEM_RELEASE);
        CloseHandle(process);
        return InjectResult::Error;
    }

    LPTHREAD_START_ROUTINE LoadLibraryA_addr = (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32_base, "LoadLibraryA");
    if (LoadLibraryA_addr == NULL)
    {
        VirtualFreeEx(process, alloc_base_addr, 0, MEM_RELEASE);
        CloseHandle(process);
        return InjectResult::Error;
    }

    HANDLE thread = CreateRemoteThread(process, NULL, 0, LoadLibraryA_addr, alloc_base_addr, 0, NULL);
    if (thread == NULL)
    {
        VirtualFreeEx(process, alloc_base_addr, 0, MEM_RELEASE);
        CloseHandle(process);
        return InjectResult::Error;
    }

    WaitForSingleObject(thread, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeThread(thread, &exitCode);

    VirtualFreeEx(process, alloc_base_addr, 0, MEM_RELEASE);
    CloseHandle(thread);
    CloseHandle(process);

    return (exitCode != 0 ? InjectResult::Sucessfully : InjectResult::Error);
}


class MainWindow : public QMainWindow
{
public:
    MainWindow(QWidget* parent = nullptr)
        : QMainWindow(parent), m_dllFilePath("")
    {
        setWindowTitle("Inject Application");
        setFixedSize(400, 400);

        QWidget* centralWidget = new QWidget(this);
        setCentralWidget(centralWidget);

        centralWidget->setStyleSheet("QWidget { background-color: black; }");

        QVBoxLayout* layout = new QVBoxLayout(centralWidget);

        QLabel* pictureLabel = new QLabel(this);
        pictureLabel->setStyleSheet("QLabel { background-color: white; }");
        layout->addWidget(pictureLabel, 1);

        QHBoxLayout* buttonLayout = new QHBoxLayout;

        QPushButton* selectDllButton = new QPushButton("Select DLL", this);
        selectDllButton->setStyleSheet("QPushButton { background-color: white; }");
        buttonLayout->addWidget(selectDllButton);

        QPushButton* injectButton = new QPushButton("Inject", this);
        injectButton->setStyleSheet("QPushButton { background-color: #800080; color: white; }");
        buttonLayout->addWidget(injectButton);

        layout->addLayout(buttonLayout);

        QLabel* enterPidLabel = new QLabel("Enter PID:", this);
        enterPidLabel->setStyleSheet("QLabel { color: white; }");
        layout->addWidget(enterPidLabel, 0, Qt::AlignCenter);

        pidLineEdit = new QLineEdit(this);
        pidLineEdit->setStyleSheet("QLineEdit { background-color: white; }");
        layout->addWidget(pidLineEdit, 0, Qt::AlignCenter);

        connect(selectDllButton, &QPushButton::clicked, this, &MainWindow::selectDll);
        connect(injectButton, &QPushButton::clicked, this, &MainWindow::injectDll);

        QTimer* timer = new QTimer(this);
        connect(timer, &QTimer::timeout, this, [pictureLabel]() {
            static int counter = 0;
            QString styleSheet = QString("QLabel { border: 2px solid rgb(%1, %2, %3); }")
                .arg(counter % 256)
                .arg((counter + 85) % 256)
                .arg((counter + 170) % 256);
            pictureLabel->setStyleSheet(styleSheet);
            counter++;
            });
        timer->start(20);
    }

private slots:
    void selectDll()
    {
        m_dllFilePath = QFileDialog::getOpenFileName(this, "Select DLL File", "", "Dynamic Link Libraries (*.dll)");
    }

    void injectDll()
    {
        QString pid = pidLineEdit->text();
        if (!m_dllFilePath.isEmpty()) {
            auto result = InjectDLL(m_dllFilePath.toStdString().c_str(), pid.toULong());
            
            switch (result)
            {
            case InjectResult::Sucessfully:
                QMessageBox::information(nullptr, "Result", "Sucessfully inject!", QMessageBox::Ok);
                break;
            case InjectResult::Error:
                QMessageBox::information(nullptr, "Result", "Error inject", QMessageBox::Ok);
                break;
            case InjectResult::NotFoundPid:
                QMessageBox::information(nullptr, "Result", "Not found pid: " + pidLineEdit->text(), QMessageBox::Ok);
                break;
            }
        }
        else {
            qDebug() << "No DLL file selected.";
        }
    }

private:
    QString m_dllFilePath;
    QLineEdit* pidLineEdit;
};

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);

    MainWindow window;
    window.show();

    return app.exec();
}
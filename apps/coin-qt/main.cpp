// coin-qt (Qt6 GUI). Built only when Qt6 found. Shares libcoin wallet via RPC.
#ifdef __has_include
#if __has_include(<QApplication>)
#include <QApplication>
#include <QLabel>
#include <QWidget>
#include <QVBoxLayout>
#include <QPushButton>
#include <QLineEdit>
#include "rpc.h"
int main(int argc,char**argv){
  QApplication app(argc,argv); QWidget w; w.setWindowTitle("Coin (CON) Wallet");
  auto* lay=new QVBoxLayout(&w); auto* lab=new QLabel("Coin CON - 1 CON = 100,000,000 swarf"); lay->addWidget(lab);
  auto* info=new QLabel("Use coin-cli for node RPC; this v0.1 GUI shows balance/address entry."); lay->addWidget(info);
  auto* addr=new QLineEdit(); addr->setPlaceholderText("CON address"); lay->addWidget(addr);
  auto* btn=new QPushButton("Refresh chain info"); lay->addWidget(btn);
  QObject::connect(btn,&QPushButton::clicked,[&,lab]{ lab->setText(QString::fromStdString(rpcCall(19443,"getblockchaininfo","{}"))); });
  w.show(); return app.exec();
}
#else
int main(){return 0;}
#endif
#else
int main(){return 0;}
#endif

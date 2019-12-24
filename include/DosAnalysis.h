/***********************************************************
 * Author: Wen Li
 * Date  : 11/08/2019
 * Describe: DosAnalysis class implementation
 * History:
   <1> 11/13/2019 , create
************************************************************/

#ifndef _DOSANALYSIS_H_
#define _DOSANALYSIS_H_
#include <BasicType.h>
#include <Log.h>
#include <pcap.h>
#include <Packet.h>
#include <Context.h>


using namespace std;

#define TRAINING_RESULT "trainning.r"
#define DEFAULT_RATE    (128)

enum
{
    MODE_TRAINING = 1,
    MODE_ANALYSIS = 2
};

enum
{
    RES_NULL  = 0,
    RES_FLOOD = 1
};


class DosAnalysis
{
protected:
    string m_Name;

protected:
    DWORD GetTrainRate ();
    VOID  SaveTrainRate (DWORD Rate);   
    User* QueryUserCtx (Packet *P);
    User* AddUserCtx (Packet *P);
    
public:
    DosAnalysis (string Name)
    {
        m_Name = Name;
    }
    
    inline string GetName ()
    {
        return m_Name;
    }

    
    virtual BOOL Run (Packet *P) = 0;
    
};

class GsFlood:public DosAnalysis
{
private:
    DWORD m_Rate;
    set<ULONG> list_src;

public:
    GsFlood (string Name):DosAnalysis(Name)
    {
        m_Rate = GetTrainRate();
        DebugLog ("module: %s, init time:%u", Name.c_str(), CLOCK_IN_SEC ());
    }
    
    BOOL Run (Packet *P);    
};

class GsTraining:public DosAnalysis
{
private:
    DWORD m_TimeInt;
    DWORD m_StartTime;

private:
    DWORD ComputeRate ();
    
public:
    GsTraining (string Name, DWORD TrainTime):DosAnalysis(Name)
    {
        m_TimeInt = TrainTime;
        m_StartTime = CLOCK_IN_SEC ();
        DebugLog ("module: %s, init time:%u", Name.c_str(), m_StartTime);
    }
    
    BOOL Run (Packet *P);
};


class AnalysisCtl
{
private:
    DWORD m_Mode;
    vector<DosAnalysis*> m_AnalysisList;

private:
    VOID AddModule (DosAnalysis *DosAly);
    VOID RunAnalysis (Packet *P);
    VOID RunTraining (Packet *P);
    
public:
    AnalysisCtl (DWORD Mode)
    {
        m_Mode = Mode;
        
        if (Mode == MODE_TRAINING)
        {
            AddModule (new GsTraining("GsTraining", 30));       
        }
        else
        {
            AddModule (new GsFlood("GsFlood"));
        }       
    }

    VOID Run (Packet *P);
};


class AnlyWrap
{
private:
    static AnalysisCtl *m_AnlyCtl;

public:
    AnlyWrap (DWORD Mode)
    {
        if (m_AnlyCtl == NULL)
        {
            m_AnlyCtl = new AnalysisCtl(Mode);
            assert (m_AnlyCtl != NULL);
        }
    }

    AnlyWrap ()
    {
        if (m_AnlyCtl == NULL)
        {
            m_AnlyCtl = new AnalysisCtl(MODE_ANALYSIS);
            assert (m_AnlyCtl != NULL);
        }
    }

    inline VOID Release ()
    {
        if (m_AnlyCtl != NULL)
        {
            delete m_AnlyCtl;
            m_AnlyCtl == NULL;
        }
    }

    inline AnalysisCtl *GetAnalysisCtl ()
    {
        return m_AnlyCtl;
    }
};


#endif 

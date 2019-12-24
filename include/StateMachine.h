
#ifndef _STATEMACHINE_H_
#define _STATEMACHINE_H_
#include <string>
#include <vector>
#include <list>
#include <set>
#include <map>
#include <stack>
#include <queue>
#include <deque>
#include <iostream>
#include <assert.h>


using namespace std;

class State
{
private:
    string   m_SateRep;
    unsigned m_Value;
    
    map<string, string> m_NxtState;

public:
    State()
    {
    }
    
    State (string Rep, unsigned Value)
    {
        m_SateRep = Rep;
        m_Value   = Value;
    }

    inline void AddNextState(string In, string Out)
    {
        m_NxtState[In] = Out;
    }

    inline string GetNextState(string In)
    {
        auto it = m_NxtState.find(In);
        if (it == m_NxtState.end())
        {
            return "";
        }

        return it->second;
    }

    inline string GetStateRep ()
    {
        return m_SateRep;
    }

    inline unsigned GetStateValue ()
    {
        return m_Value;
    }
};

class StateMachine
{
private:
    map<string, State> m_StateTable;

private:
    State* GetState (string Rep)
    {
        auto it  = m_StateTable.find(Rep);
        assert (it != m_StateTable.end());

        return &(it->second);
    }

public:   
    StateMachine ()
    { 
    }

    inline void AddState(State & S)
    {
        m_StateTable [S.GetStateRep ()] = S;
    }

    inline unsigned GetStateValue (string StateRep)
    {
        State* S = GetState (StateRep);
        assert (S != NULL);
        
        return S->GetStateValue ();
    }

    inline string RunMachine (string StateRep, string In)
    {
        State* S = GetState (StateRep);
        assert (S != NULL);
        
        string NextStateRep = S->GetNextState (In);

        return NextStateRep;
    }
};




#endif 

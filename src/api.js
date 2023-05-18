export async function loginUser({ email, password }) {
  console.log("creds",email, password)
  const authHeaders = new Headers({
    'Authorization': `Basic ${btoa(`${email}:${password}`)}`
  });

  const res = await fetch("https://journal-production-2216.up.railway.app/login", {
    method: "POST",
    headers: {
      ...authHeaders,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ email, password })
  });

  console.log(res,"responselogin")

  if (!res.ok) {
    const data = await res.json();
    console.log("err",data)
    throw {
      message: data.error,
      statusText: res.statusText,
      status: res.status
    };
  }
  //treue hduihfui
  return res.json();
}

  

export async function registerUser(data) {
    const res = await fetch("https://journal-production-2216.up.railway.app/register", {
      method: "POST",
      body: JSON.stringify(data),
      headers: {
        "Content-Type": "application/json",
      },
    });
  
    if (!res.ok) {
      const data = await res.json();
      throw {
        message: data.error,
        statusText: res.statusText,
        status: res.status,
      };
    }
  
    return res.json();
  }

  export async function createJournal(data, token) {
    console.log(data,"datsss")
    try {
      const res = await fetch("https://journal-production-2216.up.railway.app/journals", {
        method: "POST",
        body: JSON.stringify(data),
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },

      });
  
      if (!res.ok) {
        const data = await res.json();
        console.log(data,"err data")
        throw {
          message: data.error,
          statusText: res.statusText,
          status: res.status,
        };
      }
  
      const responseData = await res.json();
  
      return responseData;
    } catch (error) {
      console.error(error);
      throw error;
    }
  }

  export async function getUserJournals(token) {
    console.log("jnltoken",token)
    try {
      const res = await fetch("https://journal-production-2216.up.railway.app/user/journal", {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
  
      if (!res.ok) {
        const data = await res.json();
        throw {
          message: data.message,
          statusText: res.statusText,
          status: res.status,
        };
      }
  
      const responseData = await res.json();
      console.log("jnlresponse",responseData)
      return responseData.journals;
    } catch (error) {
      console.error(error);
      throw error;
    }
  }
  
  
  

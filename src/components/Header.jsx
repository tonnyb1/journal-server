import React from "react"
import { Link, NavLink, useNavigate } from "react-router-dom";
import logi from "../assets/react.svg"

export default function Header() {
    const navigate = useNavigate();

    const activeStyles = {
        fontWeight: "bold",
        textDecoration: "underline",
        color: "#161616"
    }
    
    function fakeLogOut() {
        localStorage.removeItem("userToken")
        localStorage.removeItem("token")
        navigate("/login")
    }

    // Check for user token in local storage
    const isLoggedIn = localStorage.getItem("userToken") !== null;
    
    return (
        <header>
            <Link className="site-logo" to="/">#DAILYJOURNAL</Link>
            <nav>
                {/* Conditional rendering based on 'isLoggedIn' */}
                {isLoggedIn ? (
                    <>
                        <button className="send-btn" onClick={fakeLogOut}>Logout</button>
                    </>
                ) : (
                    <>
                        <NavLink 
                            to="/register"
                            style={({isActive}) => isActive ? activeStyles : null}
                        >
                            SIGN UP
                        </NavLink>
                        <NavLink 
                            to="/login"
                            style={({isActive}) => isActive ? activeStyles : null}
                        >
                            LOG IN
                        </NavLink>
                    </>
                )}
            </nav>
        </header>
    )
}

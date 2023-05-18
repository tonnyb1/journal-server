
import './App.css'
import Login from './Pages/Login'
import Register from './Pages/Register'
import Home from './components/Home'
import Layout from './components/Layout'
import {
  RouterProvider,
  createBrowserRouter,
  createRoutesFromElements,
  Route,
  Link
} from "react-router-dom"

function App() {

  const router = createBrowserRouter(createRoutesFromElements(
    <Route path="/" element={<Layout />}>
        <Route path="/" element={<Home />}/> 
        <Route path="/register" element={<Register />}/>
        <Route path="/login" element={<Login />}/>
    </Route>
      
  ))

  return (
    <RouterProvider router={router}/>
  )
}

export default App

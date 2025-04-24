import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Nav, Navbar } from 'react-bootstrap';

function Navigation() {
    const location = useLocation();
    
    // Don't show navigation on landing page
    if (location.pathname === '/' || location.pathname === '/landing') {
        return null;
    }

    return (
        <Navbar bg="dark" variant="dark" expand="lg">
            <Navbar.Brand as={Link} to="/dashboard">Cyber Threat Detection</Navbar.Brand>
            <Navbar.Toggle aria-controls="basic-navbar-nav" />
            <Navbar.Collapse id="basic-navbar-nav">
                <Nav className="mr-auto">
                    <Nav.Link as={Link} to="/dashboard">Dashboard</Nav.Link>
                    <Nav.Link as={Link} to="/detection">Threat Detection</Nav.Link>
                </Nav>
            </Navbar.Collapse>
        </Navbar>
    );
}

export default Navigation;
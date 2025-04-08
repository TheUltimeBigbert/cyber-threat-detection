import { Link } from 'react-router-dom';

function Navigation() {
    return (
        <nav className="navbar navbar-expand-lg navbar-dark bg-dark">
            <div className="container">
                <Link className="navbar-brand" to="/">Cyber Security System</Link>
                <div className="navbar-nav">
                    <Link className="nav-link" to="/threats">Threat Detection</Link>
                    <Link className="nav-link" to="/dashboard">Dashboard</Link>
                </div>
            </div>
        </nav>
    );
}

export default Navigation;
const MenuIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
  </svg>
);

const Header = ({ toggleSidebar, sidebarOpen }) => {
  const currentDate = new Date().toLocaleDateString('en-US', { 
    weekday: 'long', 
    year: 'numeric', 
    month: 'long', 
    day: 'numeric' 
  });
  
  return (
    <header className="bg-dark-800 shadow-md border-b border-dark-700">
      <div className="px-4 py-3 flex items-center justify-between">
        <div className="flex items-center">
          {!sidebarOpen && (
            <button
              onClick={toggleSidebar}
              className="p-1 mr-3 rounded-md text-dark-400 hover:bg-dark-700 hover:text-white focus:outline-none"
            >
              <MenuIcon />
            </button>
          )}
          <h1 className="text-xl font-bold text-white">Security Dashboard</h1>
          <span className="ml-4 text-xs text-dark-400 hidden md:block">{currentDate}</span>
        </div>
      </div>
    </header>
  );
};

export default Header;
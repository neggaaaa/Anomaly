import React, { createContext, useState, useContext } from "react";

const DataContext = createContext();

export const DataProvider = ({ children }) => {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  const updateData = (newData) => {
    setData(newData);
    setError(null);
  };

  const setErrorMessage = (message) => {
    setError(message);
    setData(null);
  };

  return (
    <DataContext.Provider value={{ data, error, updateData, setErrorMessage }}>
      {children}
    </DataContext.Provider>
  );
};

export const useData = () => useContext(DataContext);

import React from "react";
import { uploadFile } from "../services/api";
import { useData } from "../context/DataContext";

const FileUpload = ({text}) => {
  const { updateData, setErrorMessage } = useData();

  const handleFileChange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    try {
      const result = await uploadFile(file);
      updateData(result); 
    } catch (error) {
      setErrorMessage(error.message);
    }
  };

  return (
    <div>
     <input
  type="file"
  id="fileInput"
  className="hidden"
  onChange={handleFileChange} 
/>
<label
  htmlFor="fileInput"
  className="cursor-pointer inline-block  text-white font-semibold py-2"
>
  {text}
</label>

    </div>
  );
};

export default FileUpload;

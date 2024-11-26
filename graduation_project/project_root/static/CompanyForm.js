import React from 'react';

const CompanyForm = () => {
  return (
    <div className="mb-6">
      <label htmlFor="companyName" className="block text-sm font-medium text-gray-400 mb-2">
        Company Name
      </label>
      <input
        type="text"
        id="companyName"
        name="companyName"
        className="w-full px-3 py-2 bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg text-white focus:outline-none focus:border-cyan-500 transition-colors"
        placeholder="Enter company name"
      />
    </div>
  );
};

export default CompanyForm;
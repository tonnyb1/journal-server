import React, { useState, useEffect } from "react";

const TileJournal = ({ data, position }) => {
  const [journalData, setJournalData] = useState(data);
  const [journalPosition, setJournalPosition] = useState(position);

  useEffect(() => {
    setJournalData(data);
  }, [data]);

  useEffect(() => {
    setJournalPosition(position);
  }, [position]);

  return (
    <div className="tile-journal-container">
      <h2>Journal {journalPosition}</h2>
      <div className="tile-journal-text">
        <p>{journalData}</p>
      </div>
    </div>
  );
};

export default TileJournal;

import os
import mmap
from pathlib import Path

class OptimizedLogReader:
    """Memory-efficient log file reader with mmap support and position tracking"""
    
    def __init__(self, file_path, performance_monitor=None, app_logger=None):
        self.file_path = Path(file_path)
        self.last_inode = None
        self.last_size = 0
        self.read_position = 0  
        self.performance_monitor = performance_monitor
        self.app_logger = app_logger
    
    def has_file_changed(self):
        """Check if file has been rotated or modified"""
        if not self.file_path.exists():
            return True
        
        stat = self.file_path.stat()
        current_inode = stat.st_ino
        current_size = stat.st_size
        
        if (self.last_inode and current_inode != self.last_inode) or current_size < self.read_position:
            self.read_position = 0
            if self.app_logger:
                self.app_logger.info("Log file rotation/truncation detected")
        
        self.last_inode = current_inode
        self.last_size = current_size
        
        return current_size > self.read_position
    
    def read_new_lines(self, max_lines=1000):
        """Read only new lines since last read, updating position"""
        if not self.file_path.exists():
            if self.performance_monitor:
                self.performance_monitor.metrics['file_read_errors'] += 1
            return []
        
        try:
            file_size = self.file_path.stat().st_size
            if file_size == 0:
                self.read_position = 0
                return []
            
            if file_size < self.read_position:
                self.read_position = 0
            
            if file_size <= self.read_position:
                return []
            
            lines = []
            
            with self.file_path.open('r', encoding='utf-8', errors='ignore') as f:
                f.seek(self.read_position)
                
                new_content = f.read()
                self.read_position = f.tell()  
                
                if new_content:
                    lines = [line.strip() for line in new_content.split('\n') if line.strip()]
                
                return lines[-max_lines:]
                    
        except (PermissionError, OSError) as e:
            if self.app_logger:
                self.app_logger.error(f"File read error: {e}")
            if self.performance_monitor:
                self.performance_monitor.metrics['file_read_errors'] += 1
            return []
    
    def read_recent_lines(self, max_lines=1000):
        """Read recent lines (compatibility method - uses new logic)"""
        return self.read_new_lines(max_lines)
    
    def _read_with_mmap(self, file_obj, max_lines, file_size):
        """Legacy method - not used with position tracking"""
        return []
    
    def _read_with_seek(self, file_obj, max_lines, file_size):
        """Legacy method - not used with position tracking"""
        return []
//------------------------------------------------------------------------------
// <auto-generated />
//
// This file was automatically generated by SWIG (http://www.swig.org).
// Version 3.0.7
//
// Do not make changes to this file unless you know what you are doing--modify
// the SWIG interface file instead.
//------------------------------------------------------------------------------

namespace BerkeleyDB.Internal {

using global::System;
using global::System.Runtime.InteropServices;

internal class DB_COMPACT : global::System.IDisposable {
  private global::System.Runtime.InteropServices.HandleRef swigCPtr;
  protected bool swigCMemOwn;

  internal DB_COMPACT(global::System.IntPtr cPtr, bool cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = new global::System.Runtime.InteropServices.HandleRef(this, cPtr);
  }

  internal static global::System.Runtime.InteropServices.HandleRef getCPtr(DB_COMPACT obj) {
    return (obj == null) ? new global::System.Runtime.InteropServices.HandleRef(null, global::System.IntPtr.Zero) : obj.swigCPtr;
  }

  ~DB_COMPACT() {
    Dispose();
  }

  public virtual void Dispose() {
    lock(this) {
      if (swigCPtr.Handle != global::System.IntPtr.Zero) {
        if (swigCMemOwn) {
          swigCMemOwn = false;
          libdb_csharpPINVOKE.delete_DB_COMPACT(swigCPtr);
        }
        swigCPtr = new global::System.Runtime.InteropServices.HandleRef(null, global::System.IntPtr.Zero);
      }
      global::System.GC.SuppressFinalize(this);
    }
  }

  internal uint compact_fillpercent {
    set {
      libdb_csharpPINVOKE.DB_COMPACT_compact_fillpercent_set(swigCPtr, value);
    } 
  }

  internal uint compact_timeout {
    set {
      libdb_csharpPINVOKE.DB_COMPACT_compact_timeout_set(swigCPtr, value);
    } 
  }

  internal uint compact_pages {
    set {
      libdb_csharpPINVOKE.DB_COMPACT_compact_pages_set(swigCPtr, value);
    } 
  }

  internal uint compact_empty_buckets {
    get {
      uint ret = libdb_csharpPINVOKE.DB_COMPACT_compact_empty_buckets_get(swigCPtr);
      return ret;
    } 
  }

  internal uint compact_pages_free {
    get {
      uint ret = libdb_csharpPINVOKE.DB_COMPACT_compact_pages_free_get(swigCPtr);
      return ret;
    } 
  }

  internal uint compact_pages_examine {
    get {
      uint ret = libdb_csharpPINVOKE.DB_COMPACT_compact_pages_examine_get(swigCPtr);
      return ret;
    } 
  }

  internal uint compact_levels {
    get {
      uint ret = libdb_csharpPINVOKE.DB_COMPACT_compact_levels_get(swigCPtr);
      return ret;
    } 
  }

  internal uint compact_deadlock {
    get {
      uint ret = libdb_csharpPINVOKE.DB_COMPACT_compact_deadlock_get(swigCPtr);
      return ret;
    } 
  }

  internal uint compact_pages_truncated {
    set {
      libdb_csharpPINVOKE.DB_COMPACT_compact_pages_truncated_set(swigCPtr, value);
    } 
    get {
      uint ret = libdb_csharpPINVOKE.DB_COMPACT_compact_pages_truncated_get(swigCPtr);
      return ret;
    } 
  }

  internal DB_COMPACT() : this(libdb_csharpPINVOKE.new_DB_COMPACT(), true) {
  }

}

}
